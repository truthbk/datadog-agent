memInfo := memory.CollectInfo()

// If we only want the total memory size
totalMem, err := memInfo.TotalBytes.Value()

// If we want to print non−errored values
json, warnings, err := memInfo.AsJSON()
