
module dce_rpc_enriched;

export {
    # Create an ID for our new stream. By convention, this is
    # called "LOG".
    redef enum Log::ID += { LOG };

    # Define the record type that will contain the data to log.
    type Info: record {
		ts: time &log &optional;        
		uid: string &log &optional;
        id: conn_id     &log;				
        service_name: string &log &optional;
		service_path: string  &log &optional;		
    };
}

event zeek_init(){

Log::create_stream(dce_rpc_enriched::LOG, [$columns=Info, $path="dce_rpc_enriched"]);
}

event dce_rpc_request_stub (c: connection, fid: count, ctx_id: count, opnum: count, stub: string)
{
	if (c$dce_rpc?$endpoint) 
	{
		switch (c$dce_rpc$endpoint)
		{
			case "svcctl":		
				switch (opnum)
				{
					case 12:
						local current_offset = 0;
						local policyHandle = stub[0:20];
						current_offset+=20;
						local max_count2 = bytestring_to_count(stub[current_offset:current_offset+4], T);
						current_offset+=4;
						local offset2 = bytestring_to_count(stub[current_offset:current_offset+4], T);
						current_offset+=4;
						local actual_count = bytestring_to_count(stub[current_offset:current_offset+4], T);
						current_offset+=4;
						local serviceName = stub[current_offset:current_offset+(actual_count*2)];
						current_offset+=actual_count*2 + 2;
						local display_name_referent = bytestring_to_count(stub[current_offset:current_offset+4], T);
						current_offset+=4;
						if (display_name_referent != 0) {
							current_offset += 8;
							local temp = bytestring_to_count(stub[current_offset:current_offset+4], T);
							current_offset += 4;
							current_offset += temp*2 + 2;
						}
						local access_mask = stub[current_offset:current_offset+4];
						current_offset += 4;
						local service_type = stub[current_offset:current_offset+4];
						current_offset += 4;
						local start_type = stub[current_offset:current_offset+4];
						current_offset += 4;
						local error_control = stub[current_offset:current_offset+4];
						current_offset += 4;
						local max_count_path = bytestring_to_count(stub[current_offset:current_offset+4], T);
						current_offset+=4;
						local offset_path = bytestring_to_count(stub[current_offset:current_offset+4], T);
						current_offset+=4;
						local actual_count_path = bytestring_to_count(stub[current_offset:current_offset+4], T);
						current_offset+=4;
						local bin_path = stub[current_offset:current_offset+(actual_count_path*2)];
						current_offset+=actual_count_path*2;


						local rec: dce_rpc_enriched::Info =[$ts=network_time(),$id=c$id, $uid=c$uid, $service_path=bin_path, $service_name=serviceName];
						#LOG::write(dce_rpc_enriched::LOG, rec);
						Log::write(dce_rpc_enriched::LOG, rec);

						break;
					default:
						break;				
				}
				break;
			default:
				break;
		}
	}
}
