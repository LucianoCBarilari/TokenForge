using System;
using System.Collections.Generic;
using System.Text;

namespace Application.Feature.AuthFeature.AuthDto;

public class UserRolesPermissionsDto
{
    public Dictionary<Guid, string> Roles { get; set; } = new();        
    public Dictionary<Guid, string> Permissions { get; set; } = new();  
}
