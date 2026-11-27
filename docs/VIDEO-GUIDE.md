# Smart Intel demo recording guide

The repository currently contains a concept preview, not a screenshot or recording of the running PyQt6 app. Do not present concept art as a real application capture.

## Suggested 90–120 second walkthrough

1. Launch Smart Intel from `desktop/main.py`.
2. Create a clearly fictional investigation case.
3. Run a passive domain lookup against a domain you own or a reserved example domain.
4. Open **OSINT Sources** and demonstrate certificate transparency or Wayback results.
5. Show the provider settings without revealing any API key.
6. Add a finding to the case and show the evidence table and UTC timestamp.
7. Open the AI Analyst and explain that evidence is sent to the selected cloud provider.
8. Show the HTML report export and the JSON/CSV/STIX/DOCX/PDF export helpers.
9. Briefly show the audit journal location and security limitations.

## Recording

- Capture the actual PyQt6 window at 1920×1080 or 1280×720.
- Use fictional/example targets and never display real API keys or private information.
- Include the OS and app version in the opening or closing slate.
- Do not claim features marked pending in the capability matrix are implemented.
- Save a real screenshot as `docs/assets/smart-intel-real-screenshot.png` and an optional demo as `docs/assets/smart-intel-demo.mp4`.
- Update the README image only after the screenshot has been captured from a running build.
