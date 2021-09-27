@load base/frameworks/notice/main
@load base/protocols/smb


export {
        redef enum Notice::Type += { 
                ## Indicates that a src ip is copying a file to a remote ip over smb2
                possible_remote_file_copy::identified 
        };

global whitelist: set[int] = { 2, 4, 5};



event smb2_create_request(c: connection, hdr: SMB2::Header, request: SMB2::CreateRequest)
{
	if (request$disposition !in whitelist){ 
	return;        
        }
    NOTICE([$note=possible_remote_file_copy::identified,
            $msg=fmt("a-file-was-remotely-copied-over-smb2"),
            $conn=c,
	    $sub=(request$filename)]);

}
}
