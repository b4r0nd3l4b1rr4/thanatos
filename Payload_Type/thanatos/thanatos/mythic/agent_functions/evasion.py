from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class AmsiPatchArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class AmsiPatchCommand(CommandBase):
    cmd = "amsi_patch"
    needs_admin = False
    help_cmd = "amsi_patch"
    description = "Patch AMSI in current process to bypass script scanning."
    version = 1
    author = "OFSTeam"
    argument_class = AmsiPatchArguments
    attackmapping = ["T1562.001"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = "Patching AMSI in current process"
        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        try:
            response_text = response if isinstance(response, str) else json.dumps(response)
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=response_text.encode(),
                )
            )
        except Exception as e:
            resp.Success = False
            resp.Error = str(e)
        return resp


class EtwPatchArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class EtwPatchCommand(CommandBase):
    cmd = "etw_patch"
    needs_admin = False
    help_cmd = "etw_patch"
    description = "Patch ETW to disable event tracing in current process."
    version = 1
    author = "OFSTeam"
    argument_class = EtwPatchArguments
    attackmapping = ["T1562.001"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        task.display_params = "Patching ETW in current process"
        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        try:
            response_text = response if isinstance(response, str) else json.dumps(response)
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=response_text.encode(),
                )
            )
        except Exception as e:
            resp.Success = False
            resp.Error = str(e)
        return resp


class UnhookArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="dll",
                cli_name="DLL",
                display_name="DLL Name",
                type=ParameterType.String,
                description="DLL to unhook (default: ntdll.dll)",
                default_value="ntdll.dll",
                parameter_group_info=[ParameterGroupInfo(required=False, group_name="Default")],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            self.add_arg("dll", "ntdll.dll")
        elif self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("dll", self.command_line)


class UnhookCommand(CommandBase):
    cmd = "unhook"
    needs_admin = False
    help_cmd = "unhook [dll_name]"
    description = "Unhook a DLL by reloading a clean copy from disk."
    version = 1
    author = "OFSTeam"
    argument_class = UnhookArguments
    attackmapping = ["T1562.001"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        dll_name = task.args.get_arg("dll")
        task.display_params = f"Unhooking {dll_name}"
        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        try:
            response_text = response if isinstance(response, str) else json.dumps(response)
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=response_text.encode(),
                )
            )
        except Exception as e:
            resp.Success = False
            resp.Error = str(e)
        return resp
