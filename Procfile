# Stamp first, then serve. The stamp is what /health reports as commit and
# content_hash; writing it HERE (rather than only on a laptop before
# `railway up`) is what makes those fields describe the container that is
# actually running. A Railway GitHub-connected deploy never touches a laptop,
# so without this line such a deploy would serve a stale stamp -- or none.
#
# `|| true` is deliberate. A stamp bug must not take production down -- an
# unstamped build still starts and /health reports "stamped": false with the
# explicit "build_info.json absent" note, which is visible. A crash-looping
# container that reports nothing is strictly worse.
web: python3 stamp_build.py --runtime || true; python mcp_server.py
