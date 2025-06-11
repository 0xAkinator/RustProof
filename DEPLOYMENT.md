# 🚀 RustProof Deployment Guide

This guide covers different deployment options for RustProof.

## Quick Docker Deployment

### Prerequisites
- Docker and Docker Compose installed
- 4GB RAM minimum
- 10GB disk space

### Steps

1. **Clone and Setup**
   ```bash
   git clone <your-repo-url>
   cd rustproof
   cp .env.example .env
   ```

2. **Configure Environment**
   Edit `.env` and `frontend/.env` with your settings:
   ```bash
   # Backend .env
   MONGO_URL=mongodb://mongodb:27017
   DB_NAME=rustproof

   # Frontend .env  
   REACT_APP_BACKEND_URL=http://localhost:8001
   ```

3. **Deploy**
   ```bash
   docker-compose up -d --build
   ```

4. **Verify**
   - Web UI: http://localhost:3000
   - API Docs: http://localhost:8001/docs
   - Health Check: http://localhost:8001/api/health

## Production Deployment

### Using Docker Swarm

```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.yml rustproof
```

### Using Kubernetes

```yaml
# rustproof-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rustproof-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rustproof-backend
  template:
    metadata:
      labels:
        app: rustproof-backend
    spec:
      containers:
      - name: backend
        image: rustproof/backend:latest
        ports:
        - containerPort: 8001
        env:
        - name: MONGO_URL
          value: "mongodb://mongodb-service:27017"
```

### Manual Installation

#### Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn server:app --host 0.0.0.0 --port 8001
```

#### Frontend Setup
```bash
cd frontend
yarn install
yarn build
# Serve with nginx or any static file server
```

#### MongoDB Setup
```bash
# Install MongoDB
# Ubuntu/Debian
sudo apt-get install mongodb

# Start MongoDB
sudo systemctl start mongodb
sudo systemctl enable mongodb
```

## Environment Variables

### Backend Environment Variables
- `MONGO_URL`: MongoDB connection string
- `DB_NAME`: Database name for RustProof
- `PORT`: Backend server port (default: 8001)

### Frontend Environment Variables
- `REACT_APP_BACKEND_URL`: Backend API URL

## Security Considerations

### Production Security
- Use HTTPS with SSL certificates
- Configure MongoDB authentication
- Set up proper firewall rules
- Enable MongoDB access control
- Use environment variables for secrets

### MongoDB Security
```javascript
// Create admin user
use admin
db.createUser({
  user: "admin",
  pwd: "secure_password",
  roles: ["userAdminAnyDatabase"]
})

// Create RustProof user
use rustproof
db.createUser({
  user: "rustproof",
  pwd: "rustproof_password", 
  roles: ["readWrite"]
})
```

## Monitoring and Logging

### Health Checks
- Backend: `GET /api/health`
- Frontend: HTTP 200 on root path
- MongoDB: Connection test via backend

### Logging
```bash
# View Docker logs
docker-compose logs -f backend
docker-compose logs -f frontend

# MongoDB logs
docker-compose logs -f mongodb
```

## Scaling

### Horizontal Scaling
```yaml
# docker-compose.yml
services:
  backend:
    deploy:
      replicas: 3
    ports:
      - "8001-8003:8001"
```

### Load Balancing
Use nginx or a cloud load balancer to distribute traffic across backend instances.

## Backup and Recovery

### MongoDB Backup
```bash
# Backup
docker exec rustproof-mongodb mongodump --out /backup

# Restore
docker exec rustproof-mongodb mongorestore /backup
```

### Application Backup
- Source code: Git repository
- Configuration: Environment files
- Data: MongoDB dumps

## Troubleshooting

### Common Issues

1. **Backend not starting**
   ```bash
   # Check logs
   docker-compose logs backend
   
   # Check MongoDB connection
   docker-compose exec mongodb mongo --eval "db.stats()"
   ```

2. **Frontend build errors**
   ```bash
   # Clear cache and rebuild
   docker-compose build --no-cache frontend
   ```

3. **MongoDB connection issues**
   ```bash
   # Check if MongoDB is running
   docker-compose ps mongodb
   
   # Test connection
   docker-compose exec backend python -c "from motor.motor_asyncio import AsyncIOMotorClient; print('OK')"
   ```

### Performance Optimization

1. **Database Indexing**
   ```javascript
   // Add indexes for better performance
   db.scans.createIndex({"created_at": -1})
   db.scans.createIndex({"session_id": 1})
   ```

2. **Caching**
   - Add Redis for session caching
   - Enable browser caching for static assets

3. **Resource Limits**
   ```yaml
   # docker-compose.yml
   services:
     backend:
       deploy:
         resources:
           limits:
             memory: 1G
             cpus: '0.5'
   ```

## Support

For deployment issues:
1. Check logs first
2. Verify environment configuration
3. Test network connectivity
4. Review resource usage

For additional help, see our [GitHub Issues](https://github.com/your-org/rustproof/issues).
