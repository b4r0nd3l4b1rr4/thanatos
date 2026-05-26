from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.MythicGoRPC import (
    SendMythicRPCFileSearch,
    MythicRPCFileSearchMessage,
)
import json


class ExecuteAssemblyArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="assembly",
                cli_name="Assembly",
                display_name="Assembly File",
                type=ParameterType.File,
                description=".NET assembly to execute",
                parameter_group_info=[ParameterGroupInfo(required=True, group_name="Default")],
            ),
            CommandParameter(
                name="arguments",
                cli_name="Arguments",
                display_name="Assembly Arguments",
                type=ParameterType.String,
                description="Arguments to pass to the assembly",
                parameter_group_info=[ParameterGroupInfo(required=False, group_name="Default")],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments provided.")
        if self.command_line[0] != "{":
            raise Exception("Expected JSON input, e.g. {'assembly': <file_id>, 'arguments': 'args'}")
        self.load_args_from_json_string(self.command_line)


class ExecuteAssemblyCommand(CommandBase):
    cmd = "execute_assembly"
    needs_admin = False
    help_cmd = "execute_assembly (modal popup)"
    description = "Load and execute a .NET assembly in-memory."
    version = 1
    author = "OFSTeam"
    argument_class = ExecuteAssemblyArguments
    attackmapping = ["T1059.001"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        file_id = task.args.get_arg("assembly")
        arguments = task.args.get_arg("arguments") or ""

        file_resp = await SendMythicRPCFileSearch(
            MythicRPCFileSearchMessage(TaskID=task.id, AgentFileId=file_id)
        )

        if not file_resp or not file_resp.Success or len(file_resp.Files) == 0:
            raise Exception("Assembly file not found. Upload a valid .NET assembly.")

        f = file_resp.Files[0]
        task.args.add_arg("assembly-file-id", f.AgentFileId)
        task.args.remove_arg("assembly")

        await MythicRPC().execute(
            "update_file",
            file_id=f.AgentFileId,
            task_id=task.id,
            delete_after_fetch=True,
            comment="Assembly prepared for execution",
        )

        task.display_params = f"Executing {f.Filename} with args: {arguments}"
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


class BofArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="bof_file",
                cli_name="BOF File",
                display_name="BOF File",
                type=ParameterType.File,
                description="Beacon Object File (COFF) to execute",
                parameter_group_info=[ParameterGroupInfo(required=True, group_name="Default")],
            ),
            CommandParameter(
                name="arguments",
                cli_name="Arguments",
                display_name="BOF Arguments",
                type=ParameterType.String,
                description="Arguments to pass to the BOF",
                parameter_group_info=[ParameterGroupInfo(required=False, group_name="Default")],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments provided.")
        if self.command_line[0] != "{":
            raise Exception("Expected JSON input, e.g. {'bof_file': <file_id>, 'arguments': 'args'}")
        self.load_args_from_json_string(self.command_line)


class BofCommand(CommandBase):
    cmd = "bof"
    needs_admin = False
    help_cmd = "bof (modal popup)"
    description = "Run a Beacon Object File (COFF loader)."
    version = 1
    author = "OFSTeam"
    argument_class = BofArguments
    attackmapping = ["T1106"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        file_id = task.args.get_arg("bof_file")
        arguments = task.args.get_arg("arguments") or ""

        file_resp = await SendMythicRPCFileSearch(
            MythicRPCFileSearchMessage(TaskID=task.id, AgentFileId=file_id)
        )

        if not file_resp or not file_resp.Success or len(file_resp.Files) == 0:
            raise Exception("BOF file not found. Upload a valid BOF/COFF file.")

        f = file_resp.Files[0]
        task.args.add_arg("bof-file-id", f.AgentFileId)
        task.args.remove_arg("bof_file")

        await MythicRPC().execute(
            "update_file",
            file_id=f.AgentFileId,
            task_id=task.id,
            delete_after_fetch=True,
            comment="BOF prepared for execution",
        )

        task.display_params = f"Executing BOF {f.Filename} with args: {arguments}"
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
