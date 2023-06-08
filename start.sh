#!/bin/bash
python app.py &
sleep 5
start chrome http://127.0.0.1:5000
