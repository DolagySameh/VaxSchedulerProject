using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using vaxScheduler.Data;
using vaxScheduler.Data.Model;
using vaxScheduler.models;
using vaxScheduler.models.repos;


namespace vaxScheduler.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        public AdminController(IRepository repo)
        {
            _repo = repo;
        }
        private readonly IRepository _repo;

        /*                                   Hashing Password                               */
        [NonAction]
        [ApiExplorerSettings(IgnoreApi = true)]
        private string HashPassword(string password)
        {
            return _repo.HashPassword(password);
        }

        /*                                   Get VaccineCenter                             */


        [HttpGet("Get-VaccinationCenter")]

        public ActionResult<IEnumerable<VaccinationCenterDto>> GetAllVaccinationCenters()
        {
            return _repo.GetAllVaccinationCenters();
        }



        /*                                   Add-vaccinationCenter                           */
        [HttpPost("Add-vaccinationCenter")]
        [Authorize(Roles = "Admin")]
        public ActionResult<VaccinationCenterDto> AddVaccinationCenter([FromBody] VaccinationCenterDto centerDTO)
        {
            return _repo.AddVaccinationCenter(centerDTO);
        }



        /*                                    update VaccinationCenter                           */
        [Authorize(Roles = "Admin")]
        [HttpPut("update-VaccinationCenter/{centerId}")]
        public IActionResult UpdateVaccinationCenter(int centerId, [FromBody] VaccinationCenterDto centerDTO)
        {
            return _repo.UpdateVaccinationCenter(centerId, centerDTO);
        }



        /*                                          delete VaccinationCenter                         */
        [HttpDelete("delete-vaccinationCenter/{centerId}")]
        [Authorize(Roles = "Admin")]
        public IActionResult DeleteVaccinationCenter(int centerId)
        {
           return _repo.DeleteVaccinationCenter(centerId);
        }


        /*                                          Get Vaccines                        */
        [HttpGet("vaccination-centers/{centerId}/Get-vaccines")]
        [Authorize(Roles = "Admin")]
        public ActionResult<IEnumerable<VaccineDTO>> GetVaccinesForCenter(int centerId)
        {
            return _repo.GetVaccinesForCenter(centerId);
        }

        /*                                          Add Vaccine                        */
        [HttpPost("vaccination-centers/{centerId}/add-vaccines")]
        [Authorize(Roles = "Admin")]
        public ActionResult<VaccineDTO> AddVaccineForCenter([FromRoute] int centerId, [FromBody] VaccineDTO vaccineDTO)
        {
            return _repo.AddVaccineForCenter(centerId, vaccineDTO);
        }

        /*                                          update Vaccine                       */
        [HttpPut("vaccination-centers/{centerId}/update-vaccines/{vaccineId}")]
        [Authorize(Roles = "Admin")]
        public IActionResult UpdateVaccineForCenter([FromRoute] int centerId, [FromRoute] int vaccineId, [FromBody] VaccineDTO vaccineDTO)
        {
            return _repo.UpdateVaccineForCenter(centerId, vaccineId, vaccineDTO);
        }

        /*                                          delete Vaccine                        */
        [HttpDelete("vaccination-centers/{centerId}/delete-vaccines/{vaccineId}")]
        [Authorize(Roles = "Admin")]
        public IActionResult DeleteVaccineForCenter(int centerId, int vaccineId)
        {
            return _repo.DeleteVaccineForCenter(centerId, vaccineId);
        }

        /*                                      Get pending-registeration                            */
        [HttpGet("pending-registrations")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetPendingRegistrations()
        {
            return _repo.GetPendingRegistrations();
        }


        /*                                      Accept Registered User                            */
        [HttpPut("approve-registration/{userId}")]
        [Authorize(Roles = "Admin")]
        public IActionResult ApproveRegistration(string userId)
        {
           return _repo.ApproveRegistration(userId);
        }



        /*                                    Reject Registered User                            */
        [HttpPut("reject-registration/{userId}")]
        [Authorize(Roles = "Admin")]
        public IActionResult RejectRegistration(string userId)
        {
            return _repo.RejectRegistration(userId);
        }





        /*
                [HttpPost("AddRoles")]
                public async Task<IActionResult> CreateRole([FromBody] dtoAddRole model)
                {
                    var roleExists = await _roleManager.RoleExistsAsync(model.name);
                    if (!roleExists)
                    {
                        var role = new IdentityRole<int>(model.name);
                        var result = await _roleManager.CreateAsync(role);
                        if (result.Succeeded)
                        {
                            return Ok($"Role '{model.name}' created successfully");
                        }
                        return BadRequest(result.Errors);
                    }
                    return BadRequest($"Role '{model.name}' already exists");
                }*/

        /*                                  Admin  Register only first time                              *//*
        private string HashPassword(string password)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(password));
        }

        [HttpPost("admin-register")]
        public async Task<IActionResult> AdminRegister([FromBody] RegisterDto registerDto)
        {
           

            var user = new User
            {
                LastName = registerDto.LastName,
                FirstName = registerDto.FirstName,
                UserName = registerDto.UserName,
                Email = registerDto.Email,
                
                // Additional properties for the user, if any
            };

            var result = await _userManager.CreateAsync(user, HashPassword(registerDto.Password));

            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            // Add user to Admin role
            await _userManager.AddToRoleAsync(user, "Admin");

            return Ok("Admin user created successfully");
        }*/




    }
}
