  method auth_check_internal.

    data: ls_auth_object_cache type ty_authority_object
        , lv_tabix             type sy-tabix
        .

    " Reading auth cache
    read table gt_cache_authority_object into ls_auth_object_cache
      with key authtype = iv_authtype
               act      = iv_act
               grp      = iv_grp
               sys      = iv_sys
               rol      = iv_rol
               pro      = iv_pro
               obj      = iv_obj
               aut      = iv_aut
               secpol   = iv_secpol
      binary search.

    lv_tabix = sy-tabix.

    if sy-subrc eq 0. "Authority check for this object is in cache
      ev_return = ls_auth_object_cache-return.
      return.
    endif.


    " --- authority check
    case iv_authtype.
      when obj_group.
        " 'S_USER_GRP'
        if iv_grp = space.
          authority-check object 'S_USER_GRP'
            id 'CLASS' dummy
            id 'ACTVT' field iv_act.
        else.
          authority-check object 'S_USER_GRP'
            id 'CLASS' field iv_grp
            id 'ACTVT' field iv_act.
        endif.

      when obj_auth.
        " 'S_USER_AUT'
        if iv_obj = space and iv_aut = space.
          authority-check object 'S_USER_AUT'
            id 'OBJECT' dummy
            id 'AUTH'   dummy
            id 'ACTVT'  field iv_act.
        else.
          if iv_obj = space.
            authority-check object 'S_USER_AUT'
              id 'OBJECT' dummy
              id 'AUTH'   field iv_aut
              id 'ACTVT'  field iv_act.
          else.
            if iv_aut = space.
              authority-check object 'S_USER_AUT'
                id 'OBJECT' field iv_obj
                id 'AUTH'   dummy
                id 'ACTVT'  field iv_act.
            else.
              authority-check object 'S_USER_AUT'
                id 'OBJECT' field iv_obj
                id 'AUTH'   field iv_aut
                id 'ACTVT'  field iv_act.
            endif.
          endif.
        endif.

      when obj_sys.
        " 'S_USER_SYS'
        if iv_sys = space.
          authority-check object 'S_USER_SYS'
            id 'SUBSYSTEM' dummy
            id 'ACTVT'     field iv_act.
        else.
          authority-check object 'S_USER_SYS'
            id 'SUBSYSTEM' field iv_sys
            id 'ACTVT'     field iv_act.
        endif.

      when obj_agr.
        " 'S_USER_AGR'
        if iv_rol = space.
          authority-check object 'S_USER_AGR'
            id 'ACT_GROUP' dummy
            id 'ACTVT'     field iv_act.
        else.
          authority-check object 'S_USER_AGR'
            id 'ACT_GROUP' field iv_rol
            id 'ACTVT'     field iv_act.
        endif.

      when obj_pro.
        " 'S_USER_PRO'
        if iv_pro = space.
          authority-check object 'S_USER_PRO'
            id 'PROFILE' dummy
            id 'ACTVT'   field iv_act.
        else.
          authority-check object 'S_USER_PRO'
            id 'PROFILE' field iv_pro
            id 'ACTVT'   field iv_act.
        endif.

      when obj_sas.
        if iv_rol = space and iv_pro = space.
          " 'S_USER_SAS' - System assignment
          if iv_sys = space and iv_grp =  space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     dummy
              id 'SUBSYSTEM' dummy
              id 'ACT_GROUP' dummy
              id 'PROFILE'   dummy.

          elseif iv_sys =  space and iv_grp <> space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     field iv_grp
              id 'SUBSYSTEM' dummy
              id 'ACT_GROUP' dummy
              id 'PROFILE'   dummy.

          elseif iv_sys <> space and iv_grp = space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     dummy
              id 'SUBSYSTEM' field iv_sys
              id 'ACT_GROUP' dummy
              id 'PROFILE'   dummy.

          elseif  iv_sys <> space and iv_grp <> space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     field iv_grp
              id 'SUBSYSTEM' field iv_sys
              id 'ACT_GROUP' dummy
              id 'PROFILE'   dummy.
          endif.

        elseif iv_rol <> space and iv_pro = space.
          " 'S_USER_SAS' - Role assignment
          if iv_sys = space and iv_grp = space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     dummy
              id 'SUBSYSTEM' dummy
              id 'ACT_GROUP' field iv_rol
              id 'PROFILE'   dummy.

          elseif iv_sys =  space and iv_grp <> space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     field iv_grp
              id 'SUBSYSTEM' dummy
              id 'ACT_GROUP' field iv_rol
              id 'PROFILE'   dummy.

          elseif iv_sys <> space and iv_grp =  space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     dummy
              id 'SUBSYSTEM' field iv_sys
              id 'ACT_GROUP' field iv_rol
              id 'PROFILE'   dummy.

          elseif  iv_sys <> space and iv_grp <> space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     field iv_grp
              id 'SUBSYSTEM' field iv_sys
              id 'ACT_GROUP' field iv_rol
              id 'PROFILE'   dummy.
          endif.

        elseif iv_rol = space and iv_pro <> space.
          " 'S_USER_SAS' - Profile assignment
          if iv_sys = space and iv_grp = space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     dummy
              id 'SUBSYSTEM' dummy
              id 'ACT_GROUP' dummy
              id 'PROFILE'   field iv_pro.

          elseif iv_sys =  space and iv_grp <> space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     field iv_grp
              id 'SUBSYSTEM' dummy
              id 'ACT_GROUP' dummy
              id 'PROFILE'   field iv_pro.

          elseif iv_sys <> space and iv_grp = space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     dummy
              id 'SUBSYSTEM' field iv_sys
              id 'ACT_GROUP' dummy
              id 'PROFILE'   field iv_pro.

          elseif iv_sys <> space and iv_grp <> space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     field iv_grp
              id 'SUBSYSTEM' field iv_sys
              id 'ACT_GROUP' dummy
              id 'PROFILE'   field iv_pro.
          endif.

        elseif iv_rol <> space and iv_pro <> space.
          " 'S_USER_SAS' - not used
          if iv_sys = space and iv_grp = space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     dummy
              id 'SUBSYSTEM' dummy
              id 'ACT_GROUP' field iv_rol
              id 'PROFILE'   field iv_pro.

          elseif iv_sys =  space and iv_grp <> space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     field iv_grp
              id 'SUBSYSTEM' dummy
              id 'ACT_GROUP' field iv_rol
              id 'PROFILE'   field iv_pro.

          elseif iv_sys <> space and iv_grp = space.

            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     dummy
              id 'SUBSYSTEM' field iv_sys
              id 'ACT_GROUP' field iv_rol
              id 'PROFILE'   field iv_pro.

          elseif  iv_sys <> space and iv_grp <> space.
            authority-check object 'S_USER_SAS'
              id 'ACTVT'     field iv_act
              id 'CLASS'     field iv_grp
              id 'SUBSYSTEM' field iv_sys
              id 'ACT_GROUP' field iv_rol
              id 'PROFILE'   field iv_pro.
          endif.
        endif.

      when obj_secpol.
        " 'S_SECPOL'
        if iv_secpol eq space.
          authority-check object 'S_SECPOL'
                     id 'ACTVT'      field iv_act
                     id 'POLICYNAME' dummy.
        else.
          authority-check object 'S_SECPOL'
                     id 'ACTVT'      field iv_act
                     id 'POLICYNAME' field iv_secpol.
        endif.

    endcase.

    ev_return = sy-subrc.

    " Update cache
    ls_auth_object_cache-authtype = iv_authtype.
    ls_auth_object_cache-act      = iv_act.
    ls_auth_object_cache-grp      = iv_grp.
    ls_auth_object_cache-sys      = iv_sys.
    ls_auth_object_cache-rol      = iv_rol.
    ls_auth_object_cache-pro      = iv_pro.
    ls_auth_object_cache-obj      = iv_obj.
    ls_auth_object_cache-aut      = iv_aut.
    ls_auth_object_cache-secpol   = iv_secpol.
    ls_auth_object_cache-return   = sy-subrc.

    insert ls_auth_object_cache into gt_cache_authority_object index lv_tabix.

  endmethod.                    "auth_check_internal
