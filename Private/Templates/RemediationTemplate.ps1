#----------------------------------JSON object template---------------------------------------
$Script:Action1_RemediationTemplate = @'
{
  "name": "",
  "retry_minutes": "1440",
  "endpoints": [
    {
      "id": "ALL",
      "type": "EndpointGroup"
    }
  ],
  "actions": [
    {
      "name": "Deploy Update",
      "template_id": "deploy_update",
      "params": {
        "display_summary": "",
        "packages": [
          {
            "default": "default"
          }
        ],
        "update_approval": "manual",
        "automatic_approval_delay_days": 7,
        "scope": "Specified",
        "reboot_options": {
          "auto_reboot": "yes",
          "show_message": "yes",
          "message_text": "Your computer requires maintenance and will be rebooted. Please save all work and reboot now to avoid losing any data.",
          "timeout": 240
        }
      }
    }
  ]
}
'@