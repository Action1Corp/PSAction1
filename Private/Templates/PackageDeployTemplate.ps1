#----------------------------------JSON object template---------------------------------------
$Script:Action1_PackageDeployTemplate = @'
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
      "name": "Deploy Software",
      "template_id": "deploy_package",
      "params": {
        "display_summary": "",
        "packages": [
          {
            "default": "default"
          }
        ],
        "reboot_options": {
          "auto_reboot": "no"
        }
      }
    }
  ]
}
'@