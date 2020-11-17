FROM node:lts

WORKDIR /home/node/app

#copy app files into container
COPY . .

RUN npm install

CMD [ "node", "index.js", "-c", "./config.json" ]
