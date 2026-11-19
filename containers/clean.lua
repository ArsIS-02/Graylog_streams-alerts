function drop_empty_keys(tag, ts, record)
    local out = {}
    local changed = false
    for k, v in pairs(record) do
        if k == "" then changed = true else out[k] = v end
    end
    if changed then return 2, ts, out end
    return 0, ts, record
end
