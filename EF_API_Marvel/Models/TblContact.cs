using System;
using System.Collections.Generic;

namespace EF_API_Marvel.Models;

public partial class TblContact
{
    public int AvengerId { get; set; }

    public string HeroName { get; set; } = null!;

    public string RealName { get; set; } = null!;

    public string PhoneNumber { get; set; } = null!;

    public string EmailAddress { get; set; } = null!;

    public string Username { get; set; } = null!;

    public virtual TblAvenger UsernameNavigation { get; set; } = null!;
}
