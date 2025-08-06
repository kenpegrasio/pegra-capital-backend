
# Pegra Capital Backend

This part of the Pegra Capital is designed specifically to save and provide data for the frontend application.

## Getting Started

### Prerequisites

Ensure you have installed:

- Docker 
- `.env` file with appropriate values

### Installation

```bash
git clone --recursive https://github.com/kenpegrasio/pegra-capital-backend.git
cd pegra-capital-backend
```

### Build

```bash
sudo docker compose build
```

### Run

```bash
sudo docker compose up
```

## ⚙️ .env Example

```env
MONGODB_URI=<YOUR-MONGODB-URI>
JWT_SECRET="<YOUR-SECRET-TOKEN>"
```