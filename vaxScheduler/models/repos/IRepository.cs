using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace vaxScheduler.models.repos
{
    public interface IRepository
    {
        public string HashPassword(string password);
        public Task<IActionResult> Register([FromBody] RegisterDto registerDto);
        public IActionResult Login([FromBody] LoginDto loginDto);
        public string GenerateToken(List<Claim> claims);
        public IActionResult ALogout();
        public ActionResult<IEnumerable<VaccinationCenterDto>> GetAllVaccinationCenters();
        public ActionResult<VaccinationCenterDto> AddVaccinationCenter([FromBody] VaccinationCenterDto centerDTO);
        public IActionResult UpdateVaccinationCenter(int centerId, [FromBody] VaccinationCenterDto centerDTO);
        public IActionResult DeleteVaccinationCenter(int centerId);
        public ActionResult<IEnumerable<VaccineDTO>> GetVaccinesForCenter(int centerId);
        public ActionResult<VaccineDTO> AddVaccineForCenter([FromRoute] int centerId, [FromBody] VaccineDTO vaccineDTO);
        public IActionResult UpdateVaccineForCenter([FromRoute] int centerId, [FromRoute] int vaccineId, [FromBody] VaccineDTO vaccineDTO);
        public IActionResult DeleteVaccineForCenter(int centerId, int vaccineId);
        public IActionResult GetPendingRegistrations();
        public IActionResult ApproveRegistration(string userId);
        public IActionResult RejectRegistration(string userId);
        public ActionResult<IEnumerable<VaccinationCenterDto>> GetVaccinationCenters();
        public ActionResult<IEnumerable<VaccineDTO>> GetVaccinesByCenter(int centerId);
        public ActionResult ReserveDose(ReservationDTO reservationDTO);
        public ActionResult<IEnumerable<PatientDto>> GetPatientsWithFirstDose();
        public ActionResult<IEnumerable<ReservationDTO>> GetCenterReservations(int centerId);
        public ActionResult AcceptFirstDose(int reservationId);
        public ActionResult RejectFirstDose(int reservationId);
        public ActionResult AcceptSecondDose(int reservationId);
        public ActionResult RejectSecondDose(int reservationId);
    }
}
