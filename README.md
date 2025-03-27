# Student Voting System

A secure and transparent web-based voting system for student elections.

## Features

- User authentication (Student registration and login)
- Admin dashboard for managing candidates and events
- Real-time voting with vote tracking
- Secure vote casting with IP tracking
- Audit logging for all important actions
- Responsive design for all devices

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd VotingWeb
```

2. Create and activate a virtual environment:
```bash
python -m venv flaskappenv
# On Windows
flaskappenv\Scripts\activate
# On Unix or MacOS
source flaskappenv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

## Configuration

The application uses the following default settings:
- Database: SQLite (auth4.db)
- Admin email: admin@voting.com
- Admin password: admin123

For production deployment, please change these settings in `app.py`.

## Running the Application

1. Start the Flask development server:
```bash
python app.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

## Usage

### For Students
1. Register with your student email (format: studentnumber@dut4life.ac.za)
2. Login with your credentials
3. View active voting events
4. Cast your vote in active events
5. View results after voting

### For Administrators
1. Login with admin credentials
2. Manage candidates (add, edit, delete)
3. Create and manage voting events
4. Assign candidates to events
5. Monitor voting progress and results

## Security Features

- Password hashing using bcrypt
- Session management
- IP tracking for votes
- Audit logging
- Input validation
- CSRF protection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 