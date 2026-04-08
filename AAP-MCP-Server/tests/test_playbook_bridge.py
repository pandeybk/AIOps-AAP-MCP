from playbook_bridge import (
    BridgeSettings,
    _normalize_aap_url,
    build_failure_payload,
    build_success_payload,
    extract_playbook_yaml,
    parse_instruction,
)


def _settings() -> BridgeSettings:
    return BridgeSettings(
        aap_url="http://aap.example/api/controller/v2",
        aap_token=None,
        aap_username="admin",
        aap_password="secret",
        aap_verify_ssl=False,
        kafka_bootstrap_servers=["kafka:9092"],
        kafka_topic="aiops-ansible-playbook-generate-instruction",
        kafka_group_id="aap-playbook-bridge",
        kafka_auto_offset_reset="latest",
        control_plane_api_key="demo-token",
        control_plane_verify_ssl=False,
        lightspeed_template_name="Lightspeed Remediation Playbook Generator",
        lightspeed_template_id=None,
        lightspeed_prompt_var_name="lightspeed_prompt",
        provider_name="aap-lightspeed",
        request_timeout_seconds=60.0,
        poll_seconds=2.0,
        retry_sleep_seconds=5.0,
    )


def test_parse_instruction_strips_callback_contract() -> None:
    instruction = parse_instruction(
        """
Generate a reviewable Ansible playbook for IMS incident inc-42.

Incident context:
- anomaly_type: registration_storm

Generation requirements:
- Return only valid YAML.

Callback contract:
- callback_url: http://control-plane/incidents/inc-42/playbook-generation/callback
- correlation_id: corr-123
        """
    )

    assert instruction.correlation_id == "corr-123"
    assert instruction.incident_id == "inc-42"
    assert "Callback contract:" not in instruction.prompt_text
    assert "correlation_id" not in instruction.prompt_text


def test_extract_playbook_yaml_from_stdout_message() -> None:
    stdout = r'''
TASK [Display Ansible Playbook in YAML] ***************************************
ok: [localhost] => {
    "msg": "---\n- name: Restart service\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: Restart httpd\n      ansible.builtin.service:\n        name: httpd\n        state: restarted\n"
}
'''

    playbook_yaml = extract_playbook_yaml(stdout)

    assert "- name: Restart service" in playbook_yaml
    assert "ansible.builtin.service" in playbook_yaml


def test_build_payloads_include_generation_metadata() -> None:
    settings = _settings()
    instruction = parse_instruction(
        """
Generate a reviewable Ansible playbook for IMS incident inc-77.

Callback contract:
- callback_url: http://control-plane/incidents/inc-77/playbook-generation/callback
- correlation_id: corr-777
        """
    )

    success_payload = build_success_payload(
        settings,
        instruction,
        {"template_id": 17, "job_id": 91, "playbook_yaml": "---\n- hosts: localhost\n  tasks: []\n"},
    )
    failure_payload = build_failure_payload(
        settings,
        instruction,
        "Lightspeed job failed",
        job_id=91,
        template_id=17,
    )

    assert success_payload["status"] == "generated"
    assert success_payload["metadata"]["job_id"] == 91
    assert failure_payload["status"] == "failed"
    assert failure_payload["metadata"]["template_id"] == 17


def test_normalize_aap_url_supports_controller_root_or_api_path() -> None:
    assert _normalize_aap_url("http://aap-controller-service.aap.svc.cluster.local") == (
        "http://aap-controller-service.aap.svc.cluster.local/api/v2"
    )
    assert _normalize_aap_url("https://controller.example/api/controller/v2") == (
        "https://controller.example/api/controller/v2"
    )
