using backendnet.Data;
using backendnet.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace backendnet.Controllers;



[Route("api/[controller]")]
[ApiController]
[Authorize(Roles = "Administrador")]
public class UsuariosController(IdentityContext context, UserManager<CustomIdentityUser> userManager): Controller
{
    [HttpGet]
    public async Task<ActionResult<IEnumerable<CustomIdentityUserDTO>>> GetUsuarios()
    {
        var usuarios = new List<CustomIdentityUserDTO>();
        foreach( var usuario in await context.Users.AsNoTracking().ToListAsync()) 
        {
            usuarios.Add(new CustomIdentityUserDTO{
                Id = usuario.Id,
                Nombre = usuario.Nombre,
                Email = usuario.Email!,
                Rol = GetUserRol(usuario)
            });

        }
        return usuarios;
    }

    [HttpGet("{email}")]
    public async Task<ActionResult<CustomIdentityUserDTO>> GetUsuario(string email)
    {
        var usuario = await userManager.FindByEmailAsync(email);
        if (usuario == null) return NotFound();

        return new CustomIdentityUserDTO
        {
            Id = usuario.Id,
            Nombre = usuario.Nombre,
            Email = usuario.Email!,
            Rol = GetUserRol(usuario)
        };
        
    }

    [HttpPost]
    public async Task<ActionResult<CustomIdentityUserDTO>> PostUsuario(CustomIdentityUserPwdDTO usuarioDTO)
    {
        Console.WriteLine(usuarioDTO);
        var usuarioTOCreate = new CustomIdentityUser
        {
            Nombre = usuarioDTO.Nombre,
            Email = usuarioDTO.Email,
            NormalizedEmail = usuarioDTO.Email.ToUpper(),
            UserName = usuarioDTO.Email,
            NormalizedUserName = usuarioDTO.Email.ToUpper()
        };

        IdentityResult result = await userManager.CreateAsync(usuarioTOCreate, usuarioDTO.Password);
        if (!result.Succeeded) return BadRequest(new { mensaje = "El usuario no se ha podido crear"});

        result = await userManager.AddToRoleAsync(usuarioTOCreate, usuarioDTO.Rol);

        var usuarioViewModel = new CustomIdentityUserDTO
        {
            Id = usuarioTOCreate.Id,
            Nombre = usuarioDTO.Nombre,
            Email = usuarioDTO.Email,
            Rol = usuarioDTO.Rol
        };
        
        return CreatedAtAction(nameof(GetUsuario), new {email = usuarioDTO.Email}, usuarioViewModel);
    }

    [HttpPut("{email}")]
    public async Task<IActionResult> PutUsuario(string email, CustomIdentityUserDTO usuarioDTO)
    {

        if (email != usuarioDTO.Email) return BadRequest();

        var usuario = await userManager.FindByEmailAsync(email);
        if (usuario == null) return NotFound();
        
        if (await context.Roles.Where(r => r.Name == usuarioDTO.Rol).FirstOrDefaultAsync() == null) return NotFound();

        usuario.Nombre = usuarioDTO.Nombre;
        usuario.NormalizedUserName = usuarioDTO.Email.ToUpper();
        IdentityResult result = await userManager.UpdateAsync(usuario);
        if (!result.Succeeded) return BadRequest();

        foreach (var rol in await context.Roles.ToListAsync())
            await userManager.RemoveFromRoleAsync(usuario, rol.Name!);
        await userManager.AddToRoleAsync(usuario, usuarioDTO.Rol);

        return NoContent();
    }


    [HttpDelete("{email}")]
    public async Task<ActionResult> DeleteUsuario(string email)
    {
        var usuario = await userManager.FindByEmailAsync(email);
        if (usuario == null) return NotFound();

        if (usuario.Protegido) return StatusCode(StatusCodes.Status403Forbidden);

        IdentityResult result = await userManager.DeleteAsync(usuario);
        if (!result.Succeeded) return BadRequest();

        return NoContent();
    }

    private string GetUserRol(CustomIdentityUser usuario) 
    {
        var roles = userManager.GetRolesAsync(usuario).Result;
        return roles.FirstOrDefault() ?? string.Empty;
    }

}