provider clengine {
	probe clengine_update_fddelta(int fddelta, int	vdev_delta, int	server_delta, int zone_delta, int affected_vdevs,
		int affected_servers, int affected_zones, int prev_numrows, int	prev_numdevices, int rc);
}
