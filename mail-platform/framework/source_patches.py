"""Apply recorded production fixes to current same-repository sources."""


def apply(name, raw, patches):
    entry = patches.get(name)
    if entry is None:
        return raw
    text = raw.decode('utf-8').replace('\r\n', '\n')
    for hunk in entry['hunks']:
        before, after = hunk['before'], hunk['after']
        if not before or not after or before == after:
            raise ValueError('source_patch_shape:' + name)
        if text.count(after) == 1 and before not in text.replace(after, '', 1):
            continue
        if text.count(before) != 1 or after in text:
            raise ValueError('source_patch_conflict:' + name)
        text = text.replace(before, after, 1)
    return text.encode()
