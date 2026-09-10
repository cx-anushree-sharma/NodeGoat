##healthcheck missing
##copy from dependency
##The 'Dockerfile' shouldn´t contain the 'chown' flag

FROM node:12-alpine@sha256:d4b15b3d48f42059a15bd659be60afe21762aae9d6cbea6f124440895c27db68 AS dependencies
ENV WORKDIR /usr/src/app/
WORKDIR $WORKDIR
COPY package*.json $WORKDIR
RUN npm ci --production --no-cache

FROM node:12-alpine@sha256:d4b15b3d48f42059a15bd659be60afe21762aae9d6cbea6f124440895c27db68
ENV USER node
ENV WORKDIR /home/$USER/app
WORKDIR $WORKDIR
COPY --from=dependencies /usr/src/app/node_modules node_modules
RUN chown $USER:$USER $WORKDIR
#COPY --chown=node . $WORKDIR
COPY . $WORKDIR
# In production environment uncomment the next line
#RUN chown -R $USER:$USER /home/$USER && chmod -R g-s,o-rx /home/$USER && chmod -R o-wrx $WORKDIR
# Then all further actions including running the containers should be done under non-root user.
USER $USER
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4000', res => process.exit(res.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"
