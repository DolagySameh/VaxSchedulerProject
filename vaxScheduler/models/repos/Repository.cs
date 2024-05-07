using Microsoft.AspNetCore.Identity;
using vaxScheduler.Data.Model;
using vaxScheduler.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;


namespace vaxScheduler.models.repos
{
    public class Repository : IRepository
    {
        public Repository(AppDbContext db, UserManager<User> userManager,
            IConfiguration configuration,
            RoleManager<IdentityRole<int>> roleManager, IWebHostEnvironment environment)
        {
            _db = db;
            _configuration = configuration;
            _userManager = userManager;
            _roleManager = roleManager;
            _environment = environment;

        }
        private readonly AppDbContext _db;
        private readonly UserManager<User> _userManager;
        private readonly IConfiguration _configuration;
        private readonly RoleManager<IdentityRole<int>> _roleManager;
        private readonly IWebHostEnvironment _environment;

        /*                                   Hashing Password                               */
        public string HashPassword(string password)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(password));
        }

        /*                                   Patient_register                                               */
        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var user = new User
            {
                LastName = registerDto.LastName,
                FirstName = registerDto.FirstName,
                UserName = registerDto.UserName,
                Email = registerDto.Email,
            };
            var result = await _userManager.CreateAsync(user, HashPassword(registerDto.Password));

            if (!result.Succeeded)
            {
                return new BadRequestObjectResult(result.Errors);
            }
            await _userManager.AddToRoleAsync(user, "patient");
            return new OkObjectResult("Patient user created successfully");
        }

        /*                                          Login                                              */
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginDto loginDto)
        {
            var user = _userManager.FindByEmailAsync(loginDto.email).Result; // Synchronous call

            if (user == null || !_userManager.CheckPasswordAsync(user, HashPassword(loginDto.password)).Result)
            {
                return new UnauthorizedResult();
            }

            var isAdmin = _userManager.IsInRoleAsync(user, "Admin").Result; // Synchronous call
            var isVaccinationCenter = _userManager.IsInRoleAsync(user, "VaccinationCenter").Result; // Synchronous call

            if (isAdmin)
            {
                var adminClaims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, "Admin"),
        };

                var adminToken = GenerateToken(adminClaims);
                return new OkObjectResult(new { Token = adminToken });
            }
            else if (isVaccinationCenter)
            {
                var centerClaims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, "VaccinationCenter"),
        };

                var centerToken = GenerateToken(centerClaims);
                return new OkObjectResult(new { Token = centerToken });
            }
            else
            {
                var patientClaims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, "Patient"),
        };

                if (user.Status != "Accepted")
                {
                    return new UnauthorizedObjectResult("User is not approved.");
                }

                var patientToken = GenerateToken(patientClaims);
                return new OkObjectResult(new { Token = patientToken });
            }
        }


        /*                                      generate Token                                     */
        public string GenerateToken(List<Claim> claims)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:SecretKey"]));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddDays(60),
                signingCredentials: credentials
            );
            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            return tokenString;
        }

        /*                                     logout                                               */
        [HttpPost("logout")]
        public IActionResult ALogout()
        {
            return new RedirectToActionResult("login", "YourControllerName", null);
        }
        /* ////////////////////////////////////////////////////////////////////////////////////////////////////////////////// */
        /*                                   Get VaccineCenter                             */
        [HttpGet("Get-VaccinationCenter")]
        public ActionResult<IEnumerable<VaccinationCenterDto>> GetAllVaccinationCenters()
        {
            var centers = _db.VaccinationCenters.ToList();
            var centerDTOs = centers.Select(c => new VaccinationCenterDto
            {
                CenterId = c.CenterId,
                CenterName = c.CenterName,
                Location = c.Location,
                ContactInfo = c.ContactInfo,
                email = c.email,
                password = HashPassword(c.password)
            }).ToList();

            return new OkObjectResult(centerDTOs);
        }



        /*                                   Add-vaccinationCenter                           */
        [HttpPost("Add-vaccinationCenter")]
        [Authorize(Roles = "Admin")]
        public ActionResult<VaccinationCenterDto> AddVaccinationCenter([FromBody] VaccinationCenterDto centerDTO)
        {
            var createdCenter = new VaccinationCenter
            {
                CenterName = centerDTO.CenterName,
                Location = centerDTO.Location,
                email = centerDTO.email,
                ContactInfo = centerDTO.ContactInfo,
                password = HashPassword(centerDTO.password)
            };

            _db.VaccinationCenters.Add(createdCenter);
            _db.SaveChanges();

            var user = new User
            {
                UserName = centerDTO.CenterName,
                Email = centerDTO.email,
                FirstName = centerDTO.CenterName,
                LastName = centerDTO.CenterName
            };

            var result = _userManager.CreateAsync(user, HashPassword(centerDTO.password)).Result;

            if (result.Succeeded)
            {
                var roleExists = _roleManager.RoleExistsAsync("VaccinationCenter").Result;
               
                _userManager.AddToRoleAsync(user, "VaccinationCenter").Wait();
            }
            else
            {
                return new ObjectResult(result.Errors) { StatusCode = 400 };

            }

            centerDTO.CenterId = createdCenter.CenterId;
            return new ObjectResult(new { Message = "Vaccination center added successfully" }) { StatusCode = 200 };
        }




        /*                                    update VaccinationCenter                           */
        [Authorize(Roles = "Admin")]
        [HttpPut("update-VaccinationCenter/{centerId}")]
        public IActionResult UpdateVaccinationCenter(int centerId, [FromBody] VaccinationCenterDto centerDTO)
        {
            var existingCenter = _db.VaccinationCenters.Find(centerId);
            if (existingCenter == null)
            {
                return new OkObjectResult(" not found.");
            }

            existingCenter.CenterName = centerDTO.CenterName;
            existingCenter.Location = centerDTO.Location;
            existingCenter.ContactInfo = centerDTO.ContactInfo;

            var user = _userManager.FindByEmailAsync(existingCenter.email).Result; // Synchronous call
            if (user == null)
            {
                return new OkObjectResult("User not found.");
            }

            user.UserName = centerDTO.CenterName;
            user.Email = centerDTO.email;
            user.FirstName = centerDTO.CenterName;
            user.LastName = centerDTO.CenterName;
            existingCenter.email = centerDTO.email;

            var result = _userManager.UpdateAsync(user).Result; // Synchronous call
            if (!result.Succeeded)
            {
                return new OkObjectResult(result.Errors);
            }

            _db.SaveChanges();

            return new OkObjectResult(204);

        }



        /*                                          delete VaccinationCenter                         */
        [HttpDelete("delete-vaccinationCenter/{centerId}")]
        [Authorize(Roles = "Admin")]
        public IActionResult DeleteVaccinationCenter(int centerId)
        {
            var existingCenter = _db.VaccinationCenters.Find(centerId);
            if (existingCenter == null)
            {
                return new OkObjectResult("Center not found.");
            }

            var user = _userManager.Users.FirstOrDefault(u => u.Email == existingCenter.email);

            if (user != null)
            {
                var roles = _userManager.GetRolesAsync(user).Result;
                if (roles.Contains("VaccinationCenter"))
                {
                    _userManager.RemoveFromRoleAsync(user, "VaccinationCenter").Wait();
                }

                _userManager.DeleteAsync(user).Wait();
            }

            _db.VaccinationCenters.Remove(existingCenter);
            _db.SaveChanges();

            return new OkObjectResult("Deleted Successfully");
        }



        /*                                          Get Vaccines                        */
        [HttpGet("vaccination-centers/{centerId}/Get-vaccines")]
        [Authorize(Roles = "Admin")]
        public ActionResult<IEnumerable<VaccineDTO>> GetVaccinesForCenter(int centerId)
        {
            var vaccines = _db.Vaccines.Where(v => v.CenterId == centerId).ToList();
            var vaccineDTOs = vaccines.Select(v => new VaccineDTO
            {
                VaccineId = v.VaccineId,
                Name = v.VaccineName,
                Precautions = v.Precautions,
                TimeGapBetweenDoses = v.TimeGapBetweenDoses
            }).ToList();

            return new OkObjectResult(vaccineDTOs);
        }

        /*                                          Add Vaccine                        */
        [HttpPost("vaccination-centers/{centerId}/add-vaccines")]
        [Authorize(Roles = "Admin")]
        public ActionResult<VaccineDTO> AddVaccineForCenter([FromRoute] int centerId, [FromBody] VaccineDTO vaccineDTO)
        {
            var center = _db.VaccinationCenters.Find(centerId);
            if (center == null)
            {
                return new OkObjectResult("Vaccination center not found");
            }

            var newVaccine = new Vaccine
            {
                VaccineName = vaccineDTO.Name,
                Precautions = vaccineDTO.Precautions,
                TimeGapBetweenDoses = vaccineDTO.TimeGapBetweenDoses,
                CenterId = centerId
            };

            _db.Vaccines.Add(newVaccine);
            _db.SaveChanges();

            vaccineDTO.VaccineId = newVaccine.VaccineId;
            var uri = $"api/vaccination-centers/{centerId}/vaccines";
            return new ObjectResult(new { Message = "Vaccine added successfully"}) { StatusCode = 201 };

        }

        /*                                          update Vaccine                       */
        [HttpPut("vaccination-centers/{centerId}/update-vaccines/{vaccineId}")]
        [Authorize(Roles = "Admin")]
        public IActionResult UpdateVaccineForCenter([FromRoute] int centerId, [FromRoute] int vaccineId, [FromBody] VaccineDTO vaccineDTO)
        {
            var existingVaccine = _db.Vaccines.FirstOrDefault(v => v.VaccineId == vaccineId && v.CenterId == centerId);
            if (existingVaccine == null)
            {
                return new OkObjectResult("Vaccine not found for the given center");
            }

            existingVaccine.VaccineName = vaccineDTO.Name;
            existingVaccine.Precautions = vaccineDTO.Precautions;
            existingVaccine.TimeGapBetweenDoses = vaccineDTO.TimeGapBetweenDoses;

            _db.SaveChanges();

            return new OkObjectResult(204);
        }

        /*                                          delete Vaccine                        */
        [HttpDelete("vaccination-centers/{centerId}/delete-vaccines/{vaccineId}")]
        [Authorize(Roles = "Admin")]
        public IActionResult DeleteVaccineForCenter(int centerId, int vaccineId)
        {
            var existingVaccine = _db.Vaccines.FirstOrDefault(v => v.VaccineId == vaccineId && v.CenterId == centerId);
            if (existingVaccine == null)
            {
                return new OkObjectResult("Vaccine not found for the given center");
            }

            _db.Vaccines.Remove(existingVaccine);
            _db.SaveChanges();

            return new OkObjectResult("this vaccine Deleted successfully");
        }

        /*                                      Get pending-registeration                            */
        [HttpGet("pending-registrations")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetPendingRegistrations()
        {
            var pendingUsers = _userManager.Users.Where(u => u.Status == "Pending").ToList(); // Synchronous call
            return new OkObjectResult(pendingUsers.Select(u => new { u.Id, u.FirstName, u.LastName, u.Email }));
        }


        /*                                      Accept Registered User                            */
        [HttpPut("approve-registration/{userId}")]
        [Authorize(Roles = "Admin")]
        public IActionResult ApproveRegistration(string userId)
        {
            var user = _userManager.FindByIdAsync(userId).Result; // Synchronous call
            if (user == null)
            {
                return new OkObjectResult(" not found.");
            }

            user.Status = "Accepted";
            _db.SaveChanges();

            return new OkObjectResult(204);
        }



        /*                                    Reject Registered User                            */
        [HttpPut("reject-registration/{userId}")]
        [Authorize(Roles = "Admin")]
        public IActionResult RejectRegistration(string userId)
        {
            var user = _userManager.FindByIdAsync(userId).Result; // Synchronous call
            if (user == null)
            {
                return new OkObjectResult(" not found.");
            }

            _userManager.DeleteAsync(user).Wait(); // Synchronous call

           return new OkObjectResult(204);
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

        /*/////////////////////////////////////////////////////////////////////////////////////////////////////////////*/
        /*                               Get all VaccinationCenter with all vaccines                        */
        [HttpGet("GetAllVaccinationCenters")]
        [Authorize(Roles = "Patient")]
        public ActionResult<IEnumerable<VaccinationCenterDto>> GetVaccinationCenters()
        {
            var centers = _db.VaccinationCenters
                .Select(c => new VaccinationCenterDto
                {
                    CenterId = c.CenterId,
                    CenterName = c.CenterName,
                    Location = c.Location,
                    ContactInfo = c.ContactInfo,
                })
                .ToList(); // Synchronous call

            return new ObjectResult(centers) { StatusCode = 200 };

        }


        /*                             Get all vaccines related to vaccination centers                        */
        [HttpGet("{centerId}/GetVaccinesOfCenter")]
        [Authorize(Roles = "Patient")]
        public ActionResult<IEnumerable<VaccineDTO>> GetVaccinesByCenter(int centerId)
        {
            var vaccines = _db.Vaccines
                .Where(v => v.CenterId == centerId)
                .Select(v => new VaccineDTO
                {
                    VaccineId = v.VaccineId,
                    Name = v.VaccineName,
                    Precautions = v.Precautions,
                    TimeGapBetweenDoses = v.TimeGapBetweenDoses
                })
                .ToList(); // Synchronous call

            return new ObjectResult(vaccines) { StatusCode = 200 };

        }


        /*                            Reserve Vaccination (first and second Does)                                */
        [HttpPost("ReserveDose")]
        [Authorize(Roles = "Patient")]
        public ActionResult ReserveDose(ReservationDTO reservationDTO)
        {
            // Check if the patient has already reserved twice
            var existingReservationsCount = _db.Reservations
                .Where(r => r.PatientId == reservationDTO.PatientId)
                .Count();

            if (existingReservationsCount >= 2)
            {
                throw new Exception("You have already reserved twice. You cannot reserve more.");
            }

            // Check if the patient has already reserved this vaccine
            var existingReservation = _db.Reservations
                .FirstOrDefault(r => r.PatientId == reservationDTO.PatientId &&
                                     r.VaccineId == reservationDTO.VaccineId &&
                                     r.DoseNumber == reservationDTO.DoseNumber);

            if (existingReservation != null)
            {
                return new ObjectResult("You have already reserved this vaccine for the specified dose.") { StatusCode = 404 };
            }

            // Check if it's a second dose reservation and ensure the first dose is already taken
            // Check if it's a second dose reservation and ensure the first dose is already taken
            if (reservationDTO.DoseNumber == "second-does")
            {
                // Check if the patient has already reserved the first dose
                var firstDoseReservation = _db.Reservations
                    .FirstOrDefault(r => r.PatientId == reservationDTO.PatientId &&
                                         r.VaccineId == reservationDTO.VaccineId &&
                                         r.DoseNumber == "first-does");

                if (firstDoseReservation == null)
                {
                    return new ObjectResult("You need to reserve the first dose before reserving the second dose.") { StatusCode = 404 };
                }
                else
                {
                    // Check if the center has accepted the first dose reservation
                    if (firstDoseReservation.Status != "Accepted")
                    {
                        return new ObjectResult("You cannot reserve the second dose until the center accepts your first dose reservation.") { StatusCode = 404 };
                    }
                }
            }

            // Convert DTO to Reservation entity
            var reservation = new Reservation
            {
                PatientId = reservationDTO.PatientId,
                VaccineId = reservationDTO.VaccineId,
                CenterId = reservationDTO.centerId,
                DoseNumber = reservationDTO.DoseNumber.ToLower(),
                ReservationDate = reservationDTO.ReservationDate,
            };
            _db.Reservations.Add(reservation);
            _db.SaveChanges();

            return new ObjectResult($"Dose reservation ({reservationDTO.DoseNumber}) successful. Waiting for center acceptance.") { StatusCode = 200 };
        }


        /*                        cannot reserve Second does befor center accept first does                           */

        [HttpGet("GetPatientsWithFirstDose")]
        [Authorize(Roles = "VaccinationCenter")]
        public ActionResult<IEnumerable<PatientDto>> GetPatientsWithFirstDose()
        {
            var patientsWithFirstDose = _db.Reservations
                .Where(r => r.DoseNumber == "first-does")
                .Select(r => new ReservationDTO
                {
                    PatientId = r.PatientId,
                    VaccineId = r.VaccineId,
                    ReservationId = r.ReservationId,
                    ReservationDate = r.ReservationDate,
                    centerId = r.CenterId,   
                    DoseNumber = r.DoseNumber
                })
                .ToList(); // Synchronous call

            return new ObjectResult(patientsWithFirstDose) { StatusCode = 200 };
        }




        /*                                Get Certification after Second-Does                                            */


        /*[HttpGet]
        [Route("api/certificate/image/{certificateId}")]
        public async Task<IActionResult> GetCertificateImage(int certificateId)
        {
            try
            {
                var certificate = await _db.Certificates.FindAsync(certificateId);

                if (certificate == null)
                {
                    return NotFound("Certificate not found.");
                }
                return File(certificate.CertificateFilePath, "image/png");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"An error occurred: {ex.Message}");
            }
        }
*/
        /* /////////////////////////////////////////////////////////////////////////////////////////////////*/
        /*                          View patients that reserved vaccine from that vaccination center                               */
        [HttpGet("GetPatients-Reserved-withVaccinationCenter")]
        [Authorize(Roles = "VaccinationCenter")]
        public ActionResult<IEnumerable<ReservationDTO>> GetCenterReservations(int centerId)
        {
            var reservations = _db.Reservations
                .Where(r => r.CenterId == centerId) // Filter by centerId
                .Select(r => new ReservationDTO
                {
                    ReservationId = r.ReservationId,
                    PatientId = r.PatientId,
                    VaccineId = r.VaccineId,
                    centerId = r.CenterId,
                    DoseNumber = r.DoseNumber.ToString(), // Assuming dose_number is a number
                    ReservationDate = r.ReservationDate,
                })
                .ToList(); // Synchronous call

            return new ObjectResult(reservations) { StatusCode = 200 };
        }


        /*                                               Accept First Does                                  */
        [HttpPut("AcceptFirstDose")]
        [Authorize(Roles = "VaccinationCenter")]
        public ActionResult AcceptFirstDose(int reservationId)
        {
            var reservation = _db.Reservations.Find(reservationId);
            if (reservation == null)
            {
                return new ObjectResult("Reservation not found.") { StatusCode = 404 };

            }
            reservation.Status = "Accepted";
            _db.Entry(reservation).State = EntityState.Modified;

            _db.SaveChanges();

            return new ObjectResult("First dose reservation accepted successfully.") { StatusCode = 200 };

        }


        /*                                               Reject First Does                                  */
        [HttpDelete("RejectFirstDose")]
        [Authorize(Roles = "VaccinationCenter")]
        public ActionResult RejectFirstDose(int reservationId)
        {
            var reservation = _db.Reservations.Find(reservationId);
            if (reservation == null)
            {
                return new ObjectResult("Reservation not found.") { StatusCode = 404 };

            }
            _db.Reservations.Remove(reservation);
            _db.SaveChanges();

            return new ObjectResult("First dose reservation rejected and patient deleted from the database..") { StatusCode = 200 };

            
        }



        /*                                      Accept Second Does                                  */

        [HttpPut("AcceptSecondDose")]
        [Authorize(Roles = "VaccinationCenter")]
        public ActionResult AcceptSecondDose(int reservationId)
        {
            var reservation = _db.Reservations.Find(reservationId);
            if (reservation == null)
            {
                return new ObjectResult("Reservation not found.") { StatusCode = 404 };

            }
            
            reservation.Status = "Accepted";
            _db.Entry(reservation).State = EntityState.Modified;

            _db.SaveChanges();

            return new ObjectResult("Second dose reservation accepted successfully.") { StatusCode = 200 };

        }


        /*                                      Reject Second Does                                  */
        [HttpDelete("RejectSecondDose")]
        [Authorize(Roles = "VaccinationCenter")]
        public ActionResult RejectSecondDose(int reservationId)
        {
            var reservation = _db.Reservations.Find(reservationId);
            if (reservation == null)
            {
                return new ObjectResult("Reservation not found.") { StatusCode = 404 };

            }
           
            _db.Reservations.Remove(reservation);
            _db.SaveChanges();

            return new ObjectResult("Second dose reservation rejected and patient deleted from the database..") { StatusCode = 200 };
        }

    }
}
