# Network Traffic Monitoring System

This project is a Network Traffic Monitoring System designed to capture, analyze, and display network traffic data in real-time. It consists of a C++ program for packet capture and a Flask web application for data visualization.

## Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [File Structure](#file-structure)
- [Contributing](#contributing)
- [License](#license)

## Project Overview

The Network Traffic Monitoring System captures network packets, analyzes them to extract useful metrics, and displays these metrics on a web dashboard. The system is built using C++ for packet capture and analysis, and Python (Flask) for the web interface.

## Features

- Real-time packet capture and analysis
- Protocol distribution and traffic rate visualization
- Active connections display
- DNS resolution for IP addresses

## Installation

### Prerequisites

- **C++ Compiler**: Ensure you have a C++ compiler installed (e.g., `g++`).
- **Python**: Install Python 3.x and `pip`.
- **SQLite3**: Ensure SQLite3 is installed for database operations.

### Setup

1. **Clone the Repository**

   ```bash
   git clone https://github.com/haroonwajid/Network-Traffic-Monitoring-System.git
   cd Network-Traffic-Monitoring-System
   ```

2. **Compile the C++ Program**

   Run the provided script to compile the C++ code.

   ```bash
   ./compile.sh
   ```

3. **Install Python Dependencies**

   Navigate to the `webapp/app` directory and install the required Python packages.

   ```bash
   cd webapp/app
   pip install -r requirements.txt
   ```

## Usage

### Running the C++ Packet Capture

Execute the compiled C++ program to start capturing network packets.


### Running the Flask Web Application

Start the Flask server to view the web dashboard.

bash
cd webapp/app
python app.py


Access the dashboard at `http://localhost:5001` or `http://<your-ip>:5001`.

## File Structure

- **src/**: Contains the C++ source files for packet capture and analysis.
  - `main.cpp`: Entry point for the C++ application.
  - `packet_analyzer.cpp`: Implements packet analysis and database operations.

- **include/**: Header files for the C++ application.
  - `packet_analyzer.h`: Header for packet analysis functions.

- **webapp/app/**: Contains the Flask web application.
  - `app.py`: Main Flask application file.
  - `database.py`: Script for initializing the database.
  - `routes.py`: Defines the API routes for the web application.
  - `templates/dashboard.html`: HTML template for the web dashboard.

- **traffic.db**: SQLite database file for storing network metrics.

- **compile.sh**: Script to compile the C++ program.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.