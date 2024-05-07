using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using vaxScheduler.Data.Model;
using vaxScheduler.Data;
using vaxScheduler.models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using iText.Kernel.Pdf;
using iText.Layout.Element;
using Microsoft.AspNetCore.Authorization;
using vaxScheduler.models.repos;

namespace vaxScheduler.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PatientsController : ControllerBase
    {
        public PatientsController(IRepository repo)
        {
            _repo = repo;
        }
        private readonly IRepository _repo;


        /*                               Get all VaccinationCenter with all vaccines                        */
        [HttpGet("GetAllVaccinationCenters")]
        [Authorize(Roles = "Patient")]
        public ActionResult<IEnumerable<VaccinationCenterDto>> GetVaccinationCenters()
        {
            return _repo.GetVaccinationCenters();
        }


        /*                             Get all vaccines related to vaccination centers                        */
        [HttpGet("{centerId}/GetVaccinesOfCenter")]
        [Authorize(Roles = "Patient")]
        public ActionResult<IEnumerable<VaccineDTO>> GetVaccinesByCenter(int centerId)
        {
            return _repo.GetVaccinesByCenter(centerId);
        }


        /*                            Reserve Vaccination (first and second Does)                                */
        [HttpPost("ReserveDose")]
        [Authorize(Roles = "Patient")]
        public ActionResult ReserveDose(ReservationDTO reservationDTO)
        {
           return _repo.ReserveDose(reservationDTO);
        }


        /*                        cannot reserve Second does befor center accept first does                           */

        [HttpGet("GetPatientsWithFirstDose")]
        [Authorize(Roles = "VaccinationCenter")]
        public ActionResult<IEnumerable<PatientDto>> GetPatientsWithFirstDose()
        {
            return _repo.GetPatientsWithFirstDose();
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




    }
}
