FROM gitpod/workspace-full

# Stop SDKMAN from prompting e.g. "Do you want java 11.0.15-tem to be set as default? (Y/n):"
RUN bash -c "sed -i 's/sdkman_auto_answer=false/sdkman_auto_answer=true/' /home/gitpod/.sdkman/etc/config"

RUN bash -c ". /home/gitpod/.sdkman/bin/sdkman-init.sh && sdk install java 11.0.15-tem"
