To run this project you need:

1) Prerequisites
	•	Python 3.10+ (3.11 recommended)
	•	Node 18+ and npm or pnpm
	•	MongoDB running locally (mongodb://127.0.0.1:27017) or a cloud URI
	•	Internet access to XRPL Testnet (https://s.altnet.rippletest.net:51234)

2) clone this github https://github.com/Afformativ/HackTheNorth
3) Backend

   3.1 Create and activate a venv
    cd backend
    python3 -m venv .venv
    source .venv/bin/activate 

	3.2 Install dependencies
	    pip install -U pip
	    pip install -r requirements.txt

  	3.3 Run MongoDB
  		Local: ensure mongod is running
  		Atlas: put your connection string into MONGODB_URI

  	3.4 Run the server
	     python app.py

4) Frontend setup
npm install
npm start     # or: npm run dev (Vite), depending on your setup
