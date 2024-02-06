# Dynamic Header - Burp Suite Extension

Dynamic Header Setter is a Burp Suite extension that allows you to manage and apply custom HTTP headers dynamically during your testing sessions. This extension provides a user-friendly interface to save, rename, and remove sets of headers, and you can apply these headers selectively to your requests.

## Installation

1. Clone this repository or download the `DynamicHeader.py` file.
2. In Burp Suite, go to the "Extender" tab.
3. Click on the "Add" button in the "Extensions" section.
4. Select "Python" as the extension type.
5. Load the `DynamicHeader.py` file.

## Features

- **Save Headers**: Save sets of custom HTTP headers under a specific name for later use.
- **Rename Headers**: Rename existing header sets to make them more descriptive.
- **Remove Headers**: Delete header sets that you no longer need.
- **Apply Headers**: Toggle the extension to apply saved headers to outgoing requests.

## Usage

1. Open Burp Suite and navigate to the "Dynamic Headers" tab in the "Extender" section.
2. Use the provided text area to input your custom HTTP headers.
3. Click the "Save Headers" button to save the headers under a name.
4. You can also rename and remove saved header sets as needed.
5. Use the dropdown menu to select a saved header set.
6. Toggle the "ON" button to enable or disable the application of the selected headers to outgoing requests.

## Example

Let's say you have a set of custom headers that you often use during testing, such as authentication tokens or specific user-agent strings. You can save these headers with a name (e.g., "Authentication Headers") using the "Save Headers" button. Later, you can quickly apply these headers to your requests by selecting the saved set and toggling the "ON" button.

## Contributing

Contributions and feature requests are welcome! Please feel free to submit issues or pull requests to improve this Burp Suite extension.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
