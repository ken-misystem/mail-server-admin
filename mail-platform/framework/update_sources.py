"""Validate explicit source versions without guessing an intermediate release."""
from release import version


def sources(value, target):
    values = value if type(value) is list else [value]
    if (not values or any(type(item) is not str for item in values)
            or len(values) != len(set(values))):
        raise ValueError('update_source_versions')
    if any(version(item) >= version(target) for item in values):
        raise ValueError('update_source_version_order')
    return values


def select(value, installed):
    if installed not in sources(value['from_version'], value['to_version']):
        raise ValueError('update_source_version_unsupported')
    return dict(value, from_version=installed)
