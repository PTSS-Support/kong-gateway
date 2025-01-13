FROM kong/kong:3.1.1

# Create directory for custom plugins
USER root
RUN mkdir -p /usr/local/share/lua/5.1/kong/plugins/custom-auth

# Copy custom plugin files
COPY plugins/custom-auth/handler.lua /usr/local/share/lua/5.1/kong/plugins/custom-auth/
COPY plugins/custom-auth/schema.lua /usr/local/share/lua/5.1/kong/plugins/custom-auth/

# Set permissions
RUN chown -R kong:0 /usr/local/share/lua/5.1/kong/plugins/custom-auth && \
    chmod -R g+rw /usr/local/share/lua/5.1/kong/plugins/custom-auth

USER kong