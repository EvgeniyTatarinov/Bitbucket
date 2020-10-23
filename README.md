1. #### Package installation:
    - sudo apt install postgresql
    - sudo apt install python3-pip
    - sudo apt-get build-dep python3-psycopg2

2. #### Database settings:
    - create database bitbucket;
    - create user [DATABASE_USERNAME] with encrypted password '[DATABASE_PASSWORD]';
    - grant all privileges on database bitbucket to [DATABASE_USERNAME];
    - Specify database settings in the file settings.py
    
3. Install packages from a file requirements.txt
4. To perform the migration
    - alembic revision -m "create bitbucket table"
    - alembic upgrade head
    
    
