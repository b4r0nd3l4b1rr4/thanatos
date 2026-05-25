from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class LdapSearchArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="filter",
                cli_name="filter",
                display_name="LDAP Filter",
                type=ParameterType.String,
                description="LDAP search filter (e.g. '(objectClass=user)').",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
            CommandParameter(
                name="base_dn",
                cli_name="base_dn",
                display_name="Base DN",
                type=ParameterType.String,
                description="Search base DN. Leave empty to use domain root.",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
            CommandParameter(
                name="attributes",
                cli_name="attributes",
                display_name="Attributes",
                type=ParameterType.String,
                description="Comma-separated list of attributes to retrieve. Empty for all.",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=3)],
            ),
            CommandParameter(
                name="server",
                cli_name="server",
                display_name="DC Server",
                type=ParameterType.String,
                description="Target domain controller. Empty for auto-discovery.",
                default_value="",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=4)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must provide an LDAP filter.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("filter", self.command_line.strip())


class LdapSearchCommand(CommandBase):
    cmd = "ldap_search"
    needs_admin = False
    help_cmd = "ldap_search -filter '(objectClass=user)' [-base_dn DC=corp,DC=local] [-attributes cn,samAccountName]"
    description = "Execute an LDAP query against the domain controller using native Windows LDAP API."
    version = 1
    author = "b4r0n"
    argument_class = LdapSearchArguments
    attackmapping = ["T1087.002", "T1069.002"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        ldap_filter = taskData.args.get_arg("filter")
        resp.DisplayParams = f"-filter {ldap_filter}"
        return resp

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        if response:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=(response if isinstance(response, str) else json.dumps(response, indent=2)).encode(),
                )
            )
        return resp


class DomainInfoArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class DomainInfoCommand(CommandBase):
    cmd = "domain_info"
    needs_admin = False
    help_cmd = "domain_info"
    description = "Query basic domain information: domain name, forest, domain controllers, functional level."
    version = 1
    author = "b4r0n"
    argument_class = DomainInfoArguments
    attackmapping = ["T1087.002"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        if response:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=(response if isinstance(response, str) else json.dumps(response, indent=2)).encode(),
                )
            )
        return resp


class DomainUsersArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="group",
                cli_name="group",
                display_name="Group Name",
                type=ParameterType.String,
                description="Enumerate members of this group. Default: Domain Admins.",
                default_value="Domain Admins",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=1)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("group", self.command_line.strip())


class DomainUsersCommand(CommandBase):
    cmd = "domain_users"
    needs_admin = False
    help_cmd = "domain_users [-group 'Domain Admins']"
    description = "Enumerate members of a domain group via LDAP. Defaults to Domain Admins."
    version = 1
    author = "b4r0n"
    argument_class = DomainUsersArguments
    attackmapping = ["T1069.002"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        group = taskData.args.get_arg("group")
        resp.DisplayParams = f"-group {group}"
        return resp

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        if response:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=(response if isinstance(response, str) else json.dumps(response, indent=2)).encode(),
                )
            )
        return resp


class DomainComputersArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="filter",
                cli_name="filter",
                display_name="Filter",
                type=ParameterType.String,
                description="Additional filter (e.g. 'servers' for only server OS, 'dcs' for domain controllers).",
                default_value="all",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=1)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("filter", self.command_line.strip())


class DomainComputersCommand(CommandBase):
    cmd = "domain_computers"
    needs_admin = False
    help_cmd = "domain_computers [-filter all|servers|dcs]"
    description = "Enumerate domain computers via LDAP query."
    version = 1
    author = "b4r0n"
    argument_class = DomainComputersArguments
    attackmapping = ["T1018"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        filt = taskData.args.get_arg("filter")
        resp.DisplayParams = f"-filter {filt}"
        return resp

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        if response:
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=(response if isinstance(response, str) else json.dumps(response, indent=2)).encode(),
                )
            )
        return resp
