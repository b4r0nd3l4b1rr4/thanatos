from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class CleanupArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="technique",
                cli_name="technique",
                display_name="Technique",
                type=ParameterType.ChooseOne,
                choices=[
                    "tokens",
                    "socks",
                    "redirect",
                    "shellcode",
                    "files",
                    "registry",
                    "scheduled_task",
                    "service",
                    "all",
                ],
                description="Which technique artifacts to clean up.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="target",
                cli_name="target",
                display_name="Target",
                type=ParameterType.String,
                description="Optional target identifier (file path, task name, service name, registry key).",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must specify a technique to clean up.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split(None, 1)
            self.add_arg("technique", parts[0])
            if len(parts) > 1:
                self.add_arg("target", parts[1])


class CleanupCommand(CommandBase):
    cmd = "cleanup"
    needs_admin = False
    help_cmd = "cleanup -technique <technique> [-target <path|name>]"
    description = (
        "Clean up artifacts left by a specific technique. "
        "Supports: tokens, socks, redirect, shellcode, files, registry, scheduled_task, service, all."
    )
    version = 1
    author = "b4r0n"
    argument_class = CleanupArguments
    attackmapping = ["T1070"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        technique = taskData.args.get_arg("technique")
        target = taskData.args.get_arg("target") or ""
        resp.DisplayParams = f"-technique {technique}" + (f" -target {target}" if target else "")
        return resp

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        if response:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=(response if isinstance(response, str) else json.dumps(response)).encode(),
                )
            )
        return resp


class TimestompArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="File Path",
                type=ParameterType.String,
                description="Path to the file to timestomp.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="reference",
                cli_name="reference",
                display_name="Reference File",
                type=ParameterType.String,
                description="Copy timestamps from this reference file.",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must provide a file path.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            parts = self.command_line.strip().split(None, 1)
            self.add_arg("path", parts[0])
            if len(parts) > 1:
                self.add_arg("reference", parts[1])


class TimestompCommand(CommandBase):
    cmd = "timestomp"
    needs_admin = False
    help_cmd = "timestomp -path <file> [-reference <ref_file>]"
    description = "Modify file timestamps to match a reference file or reset to a neutral value."
    version = 1
    author = "b4r0n"
    argument_class = TimestompArguments
    attackmapping = ["T1070.006"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows, SupportedOS.Linux],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        path = taskData.args.get_arg("path")
        reference = taskData.args.get_arg("reference") or ""
        resp.DisplayParams = f"-path {path}" + (f" -reference {reference}" if reference else "")
        return resp

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        if response:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=(response if isinstance(response, str) else json.dumps(response)).encode(),
                )
            )
        return resp


class EventlogClearArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="log",
                cli_name="log",
                display_name="Log Name",
                type=ParameterType.String,
                description="Event log name to clear (e.g. Security, System, Application).",
                default_value="Security",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must provide an event log name.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("log", self.command_line.strip())


class EventlogClearCommand(CommandBase):
    cmd = "eventlog_clear"
    needs_admin = True
    help_cmd = "eventlog_clear -log <Security|System|Application>"
    description = "Clear a Windows event log. Requires admin privileges."
    version = 1
    author = "b4r0n"
    argument_class = EventlogClearArguments
    attackmapping = ["T1070.001"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        log_name = taskData.args.get_arg("log")
        resp.DisplayParams = f"-log {log_name}"
        return resp

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        if response:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=(response if isinstance(response, str) else json.dumps(response)).encode(),
                )
            )
        return resp
