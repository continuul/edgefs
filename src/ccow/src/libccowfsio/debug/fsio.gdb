define __get_ganesha_export
    set $export_id=$arg0
    set $node=export_by_id.cache[$export_id]
    set $offset=((size_t) &((struct gsh_export *)0)->node_k)
    set $gsh_exp=(struct gsh_export *)((char *)$node - $offset)
end

define ganesha_export
    __get_ganesha_export $arg0
    p *$gsh_exp
end

define __get_nedge_export
    __get_ganesha_export $arg0
    set $nedge_exp=(struct nedge_fsal_export *)($gsh_exp->fsal_export->sub_export)
end

define nedge_export
    __get_nedge_export $arg0
    p *$nedge_exp
end

define profile_stats
    __get_nedge_export $arg0
    set $ci=(ci_t *)$nedge_exp->ci
    set $i=0
    while $i<MAX_FSIO_API
        set $avg_time=0
        set $tmp=$ci->api_debug_stats[$i]
        if ($tmp.call_count)
            set $avg_time=($ci->api_debug_stats[$i].total_time / $ci->api_debug_stats[$i].call_count)
        end

        printf "API:%d\t\tcal_count:%10u\terr_count:%10u\tmin_time:%10u\tmax_time:%10u\ttot_time:%10u\tavg_time:%10u\n", (fsio_api)$i, $tmp.call_count,$tmp.err_count,$tmp.min_time,$tmp.max_time,$tmp.total_time,$avg_time
        set $i=($i + 1)
    end
end

define list_inodes
    __get_nedge_export $arg0
    set $inode_list=$nedge_exp->ci->inode_cache.cached_inode_list

    set $fi_queue=*(&$nedge_exp->ci->inode_cache.cached_inode_list)[0]
    while $fi_queue != $inode_list
        set $fi=((ccowfs_inode *)((char *)$fi_queue-((char *)&((ccowfs_inode*)0)->list_q)))
        print $fi
        set $fi_queue=((*(&$fi->list_q))[0])
    end
end

define find_inode
    __get_nedge_export $arg0
    set $inode_no=$arg1
    set $inode_list=$nedge_exp->ci->inode_cache.cached_inode_list

    set $fi_queue=*(&$nedge_exp->ci->inode_cache.cached_inode_list)[0]
    while $fi_queue != $inode_list
        set $fi=((ccowfs_inode *)((char *)$fi_queue-((char *)&((ccowfs_inode*)0)->list_q)))
        if ($inode_no == $fi->ino)
            print $fi
            print *$fi
            break
        end
        set $fi_queue=((*(&$fi->list_q))[0])
    end
end
