#!/bin/bash
# Wait for MinIO and create bucket
sleep 5
sudo docker exec taler-id-minio-1 sh -c 'mc alias set local http://localhost:9000 minioadmin minioadmin123 && mc mb --ignore-existing local/taler-id-documents && mc anonymous set private local/taler-id-documents' 2>/dev/null || true
echo "MinIO bucket initialized"
