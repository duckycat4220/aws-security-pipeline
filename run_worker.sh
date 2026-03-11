#!/bin/bash

echo "Ensuring SQS queue exists..."
python3 -m scripts.create_queue

echo "Starting SQS worker..."

while true
do
    python3 -m app.workers.sqs_worker
    sleep 2
done