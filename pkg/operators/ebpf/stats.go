package ebpfoperator

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/bpfstats"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// data operator methods

func (i *ebpfOperator) GlobalParams() api.Params {
	return nil
}

func (i *ebpfOperator) Init(params *params.Params) error {
	return nil
}

func (i *ebpfOperator) InstantiateDataOperator(
	gadgetCtx operators.GadgetContext, paramValues api.ParamValues,
) (operators.DataOperatorInstance, error) {
	// TODO: enable this conditionally in a smarter way
	if gadgetCtx.ImageName() != "bpfstats" {
		return nil, nil
	}

	var err error

	instance := &ebpfOperatorDataInstance{
		bpfOperator: i,
	}

	instance.ds, err = gadgetCtx.RegisterDataSource(datasource.TypeArray, "bpfstats")
	if err != nil {
		return nil, err
	}

	intervalAnn := paramValues[ParamMapIterInterval]
	if intervalAnn == "" {
		intervalAnn = "1000ms"
	}
	instance.interval, err = time.ParseDuration(intervalAnn)
	if err != nil {
		return nil, fmt.Errorf("parsing duration: %w", err)
	}

	countAnn := paramValues[ParamMapIterCount]
	if countAnn == "" {
		countAnn = "0"
	}
	instance.count, err = strconv.Atoi(countAnn)
	if err != nil {
		return nil, fmt.Errorf("parsing count: %w", err)
	}

	instance.ds.AddAnnotation(api.FetchIntervalAnnotation, intervalAnn)
	instance.ds.AddAnnotation(api.FetchCountAnnotation, countAnn)
	instance.ds.AddAnnotation("cli.clear-screen-before", "true")

	// low-level fields
	instance.progIDField, err = instance.ds.AddField("progID", api.Kind_Uint32, datasource.WithTags("type:ebpfprogid"))
	if err != nil {
		return nil, err
	}
	instance.progNameField, err = instance.ds.AddField("progName", api.Kind_String)
	if err != nil {
		return nil, err
	}

	// gadget-specific fields
	instance.gadgetNameField, err = instance.ds.AddField("gadgetName", api.Kind_String)
	if err != nil {
		return nil, err
	}
	instance.gadgetImageField, err = instance.ds.AddField("gadgetImage", api.Kind_String)
	if err != nil {
		return nil, err
	}
	instance.gadgetIDField, err = instance.ds.AddField("gadgetID", api.Kind_String)
	if err != nil {
		return nil, err
	}

	// stats fields
	instance.runtimeField, err = instance.ds.AddField("runtime", api.Kind_Uint64)
	if err != nil {
		return nil, err
	}
	instance.runcountField, err = instance.ds.AddField("runcount", api.Kind_Uint64)
	if err != nil {
		return nil, err
	}
	instance.mapMemoryField, err = instance.ds.AddField("mapMemory", api.Kind_Uint64)
	if err != nil {
		return nil, err
	}
	instance.mapCountField, err = instance.ds.AddField("mapCount", api.Kind_Uint64)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (i *ebpfOperator) InstanceParams() api.Params {
	// only when running bpfstats gadget
	return api.Params{
		{
			Key:          ParamMapIterInterval,
			Description:  "interval in which to iterate over maps",
			DefaultValue: "1000ms",
			TypeHint:     api.TypeString,
			Title:        "Map fetch interval",
		},
		{
			Key:          ParamMapIterCount,
			Description:  "number of map fetch cycles - use 0 for unlimited",
			DefaultValue: "0",
			TypeHint:     api.TypeInt,
			Title:        "Map fetch count",
		},
	}
	return nil
}

func (i *ebpfOperator) Priority() int {
	return 0
}

type ebpfOperatorDataInstance struct {
	bpfOperator *ebpfOperator
	ds          datasource.DataSource
	interval    time.Duration
	count       int
	done        chan struct{}

	// low-level fields
	progIDField   datasource.FieldAccessor
	progNameField datasource.FieldAccessor

	// gadget-specific fields
	gadgetImageField datasource.FieldAccessor
	gadgetIDField    datasource.FieldAccessor
	gadgetNameField  datasource.FieldAccessor

	// stats fields
	runtimeField   datasource.FieldAccessor
	runcountField  datasource.FieldAccessor
	mapMemoryField datasource.FieldAccessor
	mapCountField  datasource.FieldAccessor
}

func (i *ebpfOperatorDataInstance) Name() string {
	return "ebpfdataoperator"
}

type progStat struct {
	runtime  uint64
	runcount uint64
}

func (i *ebpfOperatorDataInstance) emitStats(gadgetCtx operators.GadgetContext) error {
	curID := ebpf.ProgramID(0)
	var err error

	mapSizes, err := bpfstats.GetMapsMemUsage()
	if err != nil {
		return fmt.Errorf("getting map memory usage: %w", err)
	}

	// cache for prog stats
	progStats := make(map[ebpf.ProgramID]progStat)

	arr, err := i.ds.NewPacketArray()
	if err != nil {
		return fmt.Errorf("creating new packet: %w", err)
	}

	// TODO: reduce lock contention
	i.bpfOperator.mu.Lock()

	programToGadget := make(map[ebpf.ProgramID]operators.GadgetContext)
	for ctx, gadgetObjs := range i.bpfOperator.gadgetObjs {
		for _, id := range gadgetObjs.programIDs {
			programToGadget[id] = ctx
		}
	}

	// emit all ebpf programs regardless they being part of a gadget
	var nextID ebpf.ProgramID
	for {
		nextID, err = ebpf.ProgramGetNextID(curID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			return fmt.Errorf("getting next program ID: %w", err)
		}
		if nextID <= curID {
			break
		}
		curID = nextID
		prog, err := ebpf.NewProgramFromID(curID)
		if err != nil {
			continue
		}
		pi, err := prog.Info()
		if err != nil {
			prog.Close()
			continue
		}

		d := arr.New()

		id, _ := pi.ID()
		runtime, _ := pi.Runtime()
		runcount, _ := pi.RunCount()

		progStats[ebpf.ProgramID(id)] = progStat{
			runtime:  uint64(runtime),
			runcount: uint64(runcount),
		}

		mapIDs, _ := pi.MapIDs()
		totalMemory := uint64(0)
		for _, mapID := range mapIDs {
			totalMemory += mapSizes[mapID]
		}

		i.progIDField.PutUint32(d, uint32(id))
		i.progNameField.PutString(d, pi.Name)

		// enrich with gadget information if they're part of a gadget
		if ctx, ok := programToGadget[ebpf.ProgramID(id)]; ok {
			i.gadgetIDField.PutString(d, ctx.ID())
			i.gadgetImageField.PutString(d, ctx.ImageName())
			i.gadgetNameField.PutString(d, "TODO" /*ctx.Name()*/)
		}

		i.runtimeField.PutUint64(d, uint64(runtime))
		i.runcountField.PutUint64(d, uint64(runcount))
		i.mapMemoryField.PutUint64(d, totalMemory)
		i.mapCountField.PutUint64(d, uint64(len(mapIDs)))

		arr.Append(d)

		prog.Close()
	}

	// emit consolidated information for gadgets
	for ctx, gadgetObjs := range i.bpfOperator.gadgetObjs {
		d := arr.New()

		i.gadgetIDField.PutString(d, ctx.ID())
		i.gadgetImageField.PutString(d, ctx.ImageName())
		i.gadgetNameField.PutString(d, "TODO" /*ctx.Name()*/)

		totalRuntime := uint64(0)
		totalRuncount := uint64(0)

		for _, id := range gadgetObjs.programIDs {
			progStat := progStats[id]
			totalRuntime += progStat.runtime
			totalRuncount += progStat.runcount
		}

		i.runtimeField.PutUint64(d, totalRuntime)
		i.runcountField.PutUint64(d, totalRuncount)

		totalMemory := uint64(0)
		for _, mapID := range gadgetObjs.mapIDs {
			totalMemory += mapSizes[mapID]
		}

		i.mapMemoryField.PutUint64(d, totalMemory)
		i.mapCountField.PutUint64(d, uint64(len(gadgetObjs.mapIDs)))

		arr.Append(d)
	}

	i.bpfOperator.mu.Unlock()

	i.ds.EmitAndRelease(arr)

	return nil
}

func (i *ebpfOperatorDataInstance) Start(gadgetCtx operators.GadgetContext) error {
	go func() {
		ctr := 0
		ticker := time.NewTicker(i.interval)
		for {
			select {
			case <-i.done:
				return
			case <-ticker.C:
				if err := i.emitStats(gadgetCtx); err != nil {
					gadgetCtx.Logger().Errorf("Failed to emit stats: %v",
						err)
				}
				ctr++
				if i.count > 0 && ctr >= i.count {
					// TODO: close DS
					return
				}
			}
		}
	}()

	return nil
}

func (i *ebpfOperatorDataInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}
