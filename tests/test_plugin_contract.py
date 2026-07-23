from __future__ import annotations

from pathlib import Path


def test_release_version_is_consistent_across_package_and_plugin_metadata():
    import importlib.metadata
    import tomllib
    import yaml
    from hermes_code_review import __version__

    root = Path(__file__).parents[1]
    project = tomllib.loads((root / 'pyproject.toml').read_text())
    manifest = yaml.safe_load((root / 'plugin.yaml').read_text())

    assert project['project']['version'] == manifest['version'] == __version__
    assert importlib.metadata.version('hermes-code-review') == __version__


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
    assert by_name['review_git_candidate']['schema']['parameters']['properties']['release_gate']['type'] == 'boolean'
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


def test_repo_cli_launcher_resolves_symlink_and_reports_ready(tmp_path):
    import json
    import os
    import subprocess

    root = Path(__file__).parents[1]
    launcher = root / 'scripts' / 'hermes-code-review'
    assert launcher.is_file()
    assert os.access(launcher, os.X_OK)

    home = tmp_path / 'home'
    home.mkdir()
    (home / 'config.yaml').write_text('''
delegation:
  lanes:
    critic:
      worker: hybgzs_grok45
main_token_reserve:
  workers:
    hybgzs_grok45:
      enabled: true
      base_url: https://review.example/v1
      api_key_env: REVIEW_TEST_KEY
      model: grok-4.5
      api_mode: chat_completions
''')
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    hop_dir = tmp_path / 'hop'
    hop_dir.mkdir()
    final_link = hop_dir / 'launcher-final'
    final_link.symlink_to(os.path.relpath(launcher, hop_dir))
    inner_link = hop_dir / 'launcher-hop'
    inner_link.symlink_to(final_link.absolute())
    link = bin_dir / 'hermes-code-review'
    link.symlink_to('../hop/launcher-hop')
    system_readlink = subprocess.run(
        ['sh', '-c', 'command -v readlink'], text=True, capture_output=True, check=True,
    ).stdout.strip()
    fake_readlink = bin_dir / 'readlink'
    fake_readlink.write_text(
        '#!/bin/sh\n'
        'if [ "${1:-}" = "-f" ]; then exit 64; fi\n'
        f'exec "{system_readlink}" "$@"\n'
    )
    fake_readlink.chmod(0o755)

    result = subprocess.run(
        [str(link), 'status'], text=True, capture_output=True, check=False,
        env={
            **os.environ,
            'HERMES_HOME': str(home),
            'PYTHONPATH': '',
            'REVIEW_TEST_KEY': 'fixture-value',
            'PATH': str(bin_dir) + os.pathsep + os.environ['PATH'],
        },
    )
    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload['status'] == 'READY'
    assert payload['version'] == '0.2.0'
    assert payload['fallback'] == 'fail'
