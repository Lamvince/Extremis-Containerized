FROM nginx:alpine
COPY nginx.conf /etc/nginx/nginx.conf
COPY app/html /usr/share/nginx/html
EXPOSE 80