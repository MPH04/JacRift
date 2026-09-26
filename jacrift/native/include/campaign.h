#ifndef VR_CAMPAIGN_H
#define VR_CAMPAIGN_H

/* Returns process exit code. */
int vr_cmd_run(int argc, char **argv);
int vr_cmd_replay(int argc, char **argv);
int vr_cmd_minimize(int argc, char **argv);
int vr_cmd_compare(int argc, char **argv);

#endif
