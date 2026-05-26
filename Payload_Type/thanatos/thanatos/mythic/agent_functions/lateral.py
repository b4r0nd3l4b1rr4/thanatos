from mythic_container.MythicCommandBase import (
    TaskArguments,
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    ParameterGroupInfo,
    SupportedOS,
    MythicTask,
    PTTaskMessageAllData,
    PTTaskProcessResponseMessageResponse,
    PTTaskCreateTaskingMessageResponse,
)
from mythic_container.MythicRPC import (
    SendMythicRPCResponseCreate,
    MythicRPCResponseCreateMessage,
)
from mythic_container.MythicGoRPC import (
    SendMythicRPCArtifactCreate,
    MythicRPCArtifactCreateMessage,
)


# ============================================================================
# WMI_EXEC
# ============================================================================


class WmiExecArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="host",
                type=ParameterType.String,
                description="Target hostname or IP address.",
                parameter_group_info=[ParameterGroupInfo(ui_position=1, required=True)],
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command to execute on the remote host.",
                parameter_group_info=[ParameterGroupInfo(ui_position=2, required=True)],
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Username for authentication (optional).",
                parameter_group_info=[ParameterGroupInfo(ui_position=3, required=False)],
                default_value="",
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Password for authentication (optional).",
                parameter_group_info=[ParameterGroupInfo(ui_position=4, required=False)],
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if self.tasking_location == "command_line":
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                raise ValueError("wmi_exec requires JSON arguments")

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class WmiExecCommand(CommandBase):
    cmd = "wmi_exec"
    needs_admin = False
    help_cmd = "wmi_exec"
    description = "Execute command on remote host via WMI."
    version = 1
    author = "@b4r0n"
    argument_class = WmiExecArguments
    attackmapping = ["T1047"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        host = taskData.args.get_arg("host")
        command = taskData.args.get_arg("command")
        username = taskData.args.get_arg("username")
        password = taskData.args.get_arg("password")

        artifact_msg = f"wmic /node:\"{host}\" process call create \"{command}\""
        if username:
            artifact_msg = f"wmic /node:\"{host}\" /user:\"{username}\" /password:\"***\" process call create \"{command}\""

        await SendMythicRPCArtifactCreate(
            MythicRPCArtifactCreateMessage(
                TaskID=taskData.Task.ID,
                ArtifactMessage=artifact_msg,
                BaseArtifactType="Process Create",
            )
        )

        display_params = f"-host {host} -command {command}"
        if username:
            display_params += f" -username {username}"

        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
            DisplayParams=display_params,
        )

    async def process_response(
        self, task: PTTaskMessageAllData, response: str
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp


# ============================================================================
# PSEXEC
# ============================================================================


class PsexecArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="host",
                type=ParameterType.String,
                description="Target hostname or IP address.",
                parameter_group_info=[ParameterGroupInfo(ui_position=1, required=True)],
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command to execute on the remote host.",
                parameter_group_info=[ParameterGroupInfo(ui_position=2, required=True)],
            ),
            CommandParameter(
                name="service_name",
                type=ParameterType.String,
                description="Service name to create (default: thanatos_svc).",
                parameter_group_info=[ParameterGroupInfo(ui_position=3, required=False)],
                default_value="thanatos_svc",
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Username for authentication (optional).",
                parameter_group_info=[ParameterGroupInfo(ui_position=4, required=False)],
                default_value="",
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Password for authentication (optional).",
                parameter_group_info=[ParameterGroupInfo(ui_position=5, required=False)],
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if self.tasking_location == "command_line":
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                raise ValueError("psexec requires JSON arguments")

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class PsexecCommand(CommandBase):
    cmd = "psexec"
    needs_admin = True
    help_cmd = "psexec"
    description = "Execute command on remote host via service creation (PsExec-style)."
    version = 1
    author = "@b4r0n"
    argument_class = PsexecArguments
    attackmapping = ["T1021.002"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        host = taskData.args.get_arg("host")
        command = taskData.args.get_arg("command")
        service_name = taskData.args.get_arg("service_name")
        username = taskData.args.get_arg("username")

        artifact_msg = f"sc \\\\{host} create {service_name} binpath=\"cmd /c {command}\""

        await SendMythicRPCArtifactCreate(
            MythicRPCArtifactCreateMessage(
                TaskID=taskData.Task.ID,
                ArtifactMessage=artifact_msg,
                BaseArtifactType="Process Create",
            )
        )

        display_params = f"-host {host} -command {command} -service_name {service_name}"
        if username:
            display_params += f" -username {username}"

        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
            DisplayParams=display_params,
        )

    async def process_response(
        self, task: PTTaskMessageAllData, response: str
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp


# ============================================================================
# WINRM_EXEC
# ============================================================================


class WinrmExecArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="host",
                type=ParameterType.String,
                description="Target hostname or IP address.",
                parameter_group_info=[ParameterGroupInfo(ui_position=1, required=True)],
            ),
            CommandParameter(
                name="command",
                type=ParameterType.String,
                description="Command to execute on the remote host.",
                parameter_group_info=[ParameterGroupInfo(ui_position=2, required=True)],
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                description="Username for authentication (optional).",
                parameter_group_info=[ParameterGroupInfo(ui_position=3, required=False)],
                default_value="",
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                description="Password for authentication (optional).",
                parameter_group_info=[ParameterGroupInfo(ui_position=4, required=False)],
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if self.tasking_location == "command_line":
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                raise ValueError("winrm_exec requires JSON arguments")

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class WinrmExecCommand(CommandBase):
    cmd = "winrm_exec"
    needs_admin = False
    help_cmd = "winrm_exec"
    description = "Execute command on remote host via WinRM."
    version = 1
    author = "@b4r0n"
    argument_class = WinrmExecArguments
    attackmapping = ["T1021.006"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        host = taskData.args.get_arg("host")
        command = taskData.args.get_arg("command")
        username = taskData.args.get_arg("username")

        artifact_msg = f"Invoke-Command -ComputerName {host} -ScriptBlock {{ {command} }}"
        if username:
            artifact_msg += " -Credential <provided>"

        await SendMythicRPCArtifactCreate(
            MythicRPCArtifactCreateMessage(
                TaskID=taskData.Task.ID,
                ArtifactMessage=artifact_msg,
                BaseArtifactType="Process Create",
            )
        )

        display_params = f"-host {host} -command {command}"
        if username:
            display_params += f" -username {username}"

        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
            DisplayParams=display_params,
        )

    async def process_response(
        self, task: PTTaskMessageAllData, response: str
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
