FROM node:latest
RUN mkdir -p /usr/src/klnet.owner.oauth
WORKDIR /usr/src/klnet.owner.oauth
COPY package.json ./
RUN yarn install
RUN apt-get update
COPY . .
EXPOSE 5002
CMD ["node","server"]