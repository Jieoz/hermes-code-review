from __future__ import annotations

from pathlib import Path


def test_plugin_registers_first_class_review_tools():
    from hermes_code_review.plugin import register

    calls = []

    class Context:
        def register_tool(self, **kwargs):
            calls.append(kwargs)

    register(Context())
    by_name = {call['name']: call for call in calls}
    assert set(by_name) == {'review_git_candidate', 'code_review_status'}
    assert by_name['review_git_candidate']['toolset'] == 'code_review'
    assert by_name['review_git_candidate']['schema']['parameters']['required'] == ['repo']
    assert by_name['review_git_candidate'].get('override') is not True


def test_manifest_matches_registered_tools():
    import yaml

    manifest = yaml.safe_load((Path(__file__).parents[1] / 'plugin.yaml').read_text())
    assert manifest['name'] == 'hermes-code-review'
    assert manifest['provides_tools'] == ['review_git_candidate', 'code_review_status']


def test_drop_in_plugin_root_loads_without_installing_package():
    import importlib.util
    import sys
    root = Path(__file__).parents[1]
    spec = importlib.util.spec_from_file_location(
        'drop_in_code_review', root / '__init__.py',
        submodule_search_locations=[str(root)],
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    assert callable(module.register)
