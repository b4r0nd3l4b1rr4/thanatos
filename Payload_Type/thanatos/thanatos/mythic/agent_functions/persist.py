from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


# ============================================================================
# persist_schtask - Create/delete scheduled task persistence
# ============================================================================
class PersistSchtaskArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="name",
                cli_name="name",
                display_name="Task Name",
                type=ParameterType.String,
                description="Name of the scheduled task.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="action",
                cli_name="action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["create", "delete"],
                default_value="create",
                description="Create or delete the scheduled task.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
            CommandParameter(
                name="command",
                cli_name="command",
                display_name="Command",
                type=ParameterType.String,
                description="Command to execute (required for create).",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=3)],
            ),
            CommandParameter(
                name="schedule",
                cli_name="schedule",
                display_name="Schedule",
                type=ParameterType.String,
                description="Schedule specification (e.g., 'DAILY /ST 09:00').",
                default_value="DAILY /ST 09:00",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=4)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must provide parameters for persist_schtask.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Use JSON format for persist_schtask parameters.")


class PersistSchtaskCommand(CommandBase):
    cmd = "persist_schtask"
    needs_admin = False
    help_cmd = "persist_schtask -name <name> -action {create|delete} -command <cmd> -schedule <schedule>"
    description = "Create or delete a scheduled task for persistence."
    version = 1
    author = "@RedTeamGPT"
    argument_class = PersistSchtaskArguments
    attackmapping = ["T1053.005"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        name = taskData.args.get_arg("name")
        action = taskData.args.get_arg("action")
        command = taskData.args.get_arg("command") or ""
        schedule = taskData.args.get_arg("schedule") or "DAILY /ST 09:00"
        resp.DisplayParams = f"-name {name} -action {action}"
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


# ============================================================================
# persist_registry - Create/delete registry persistence
# ============================================================================
class PersistRegistryArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["create", "delete"],
                default_value="create",
                description="Create or delete the registry entry.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="key",
                cli_name="key",
                display_name="Registry Key",
                type=ParameterType.String,
                description="Registry key path.",
                default_value="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
            CommandParameter(
                name="name",
                cli_name="name",
                display_name="Value Name",
                type=ParameterType.String,
                description="Registry value name.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=3)],
            ),
            CommandParameter(
                name="value",
                cli_name="value",
                display_name="Value Data",
                type=ParameterType.String,
                description="Registry value data (required for create).",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=4)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must provide parameters for persist_registry.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Use JSON format for persist_registry parameters.")


class PersistRegistryCommand(CommandBase):
    cmd = "persist_registry"
    needs_admin = False
    help_cmd = "persist_registry -action {create|delete} -key <key> -name <name> -value <data>"
    description = "Create or delete a registry Run key for persistence."
    version = 1
    author = "@RedTeamGPT"
    argument_class = PersistRegistryArguments
    attackmapping = ["T1547.001"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        action = taskData.args.get_arg("action")
        key = taskData.args.get_arg("key") or "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        name = taskData.args.get_arg("name")
        value = taskData.args.get_arg("value") or ""
        resp.DisplayParams = f"-action {action} -name {name}"
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


# ============================================================================
# persist_service - Create/delete service persistence
# ============================================================================
class PersistServiceArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["create", "delete"],
                default_value="create",
                description="Create or delete the service.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="name",
                cli_name="name",
                display_name="Service Name",
                type=ParameterType.String,
                description="Name of the service.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
            CommandParameter(
                name="display_name",
                cli_name="display_name",
                display_name="Display Name",
                type=ParameterType.String,
                description="Display name of the service (required for create).",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=3)],
            ),
            CommandParameter(
                name="bin_path",
                cli_name="bin_path",
                display_name="Binary Path",
                type=ParameterType.String,
                description="Binary path for the service (required for create).",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=4)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must provide parameters for persist_service.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Use JSON format for persist_service parameters.")


class PersistServiceCommand(CommandBase):
    cmd = "persist_service"
    needs_admin = True
    help_cmd = "persist_service -action {create|delete} -name <name> -display_name <name> -bin_path <path>"
    description = "Create or delete a Windows service for persistence. Requires admin privileges."
    version = 1
    author = "@RedTeamGPT"
    argument_class = PersistServiceArguments
    attackmapping = ["T1543.003"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        action = taskData.args.get_arg("action")
        name = taskData.args.get_arg("name")
        display_name = taskData.args.get_arg("display_name") or ""
        bin_path = taskData.args.get_arg("bin_path") or ""
        resp.DisplayParams = f"-action {action} -name {name}"
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


# ============================================================================
# persist_wmi - Create/delete WMI event subscription persistence
# ============================================================================
class PersistWmiArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["create", "delete"],
                default_value="create",
                description="Create or delete the WMI event subscription.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="name",
                cli_name="name",
                display_name="Subscription Name",
                type=ParameterType.String,
                description="Name of the WMI event subscription.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=2)],
            ),
            CommandParameter(
                name="command",
                cli_name="command",
                display_name="Command",
                type=ParameterType.String,
                description="Command to execute (required for create).",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=3)],
            ),
            CommandParameter(
                name="trigger",
                cli_name="trigger",
                display_name="Trigger",
                type=ParameterType.String,
                description="Trigger condition (e.g., 'startup' or WQL filter).",
                default_value="startup",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=4)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must provide parameters for persist_wmi.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Use JSON format for persist_wmi parameters.")


class PersistWmiCommand(CommandBase):
    cmd = "persist_wmi"
    needs_admin = True
    help_cmd = "persist_wmi -action {create|delete} -name <name> -command <cmd> -trigger <trigger>"
    description = "Create or delete a WMI event subscription for persistence. Requires admin privileges."
    version = 1
    author = "@RedTeamGPT"
    argument_class = PersistWmiArguments
    attackmapping = ["T1546.003"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        action = taskData.args.get_arg("action")
        name = taskData.args.get_arg("name")
        command = taskData.args.get_arg("command") or ""
        trigger = taskData.args.get_arg("trigger") or "startup"
        resp.DisplayParams = f"-action {action} -name {name}"
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
